rule TTP_XOR_QUAD_CurrentVersionRun_8a28 {
  strings:
    $key_8a28 = { d9 47 [2] fd 49 [2] d6 65 [2] f8 47 [2] ec 5c [2] e3 46 [2] fd 5b [2] ff 5a [2] e4 5c [2] f8 5b [2] e4 74 }

  condition:
    any of them
}