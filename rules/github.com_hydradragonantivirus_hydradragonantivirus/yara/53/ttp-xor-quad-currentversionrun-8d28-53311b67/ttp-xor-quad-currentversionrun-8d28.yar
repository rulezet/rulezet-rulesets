rule TTP_XOR_QUAD_CurrentVersionRun_8d28 {
  strings:
    $key_8d28 = { de 47 [2] fa 49 [2] d1 65 [2] ff 47 [2] eb 5c [2] e4 46 [2] fa 5b [2] f8 5a [2] e3 5c [2] ff 5b [2] e3 74 }

  condition:
    any of them
}