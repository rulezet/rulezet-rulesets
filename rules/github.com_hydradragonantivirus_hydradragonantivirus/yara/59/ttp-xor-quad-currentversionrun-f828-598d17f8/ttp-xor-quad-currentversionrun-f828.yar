rule TTP_XOR_QUAD_CurrentVersionRun_f828 {
  strings:
    $key_f828 = { ab 47 [2] 8f 49 [2] a4 65 [2] 8a 47 [2] 9e 5c [2] 91 46 [2] 8f 5b [2] 8d 5a [2] 96 5c [2] 8a 5b [2] 96 74 }

  condition:
    any of them
}