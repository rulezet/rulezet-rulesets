rule TTP_XOR_QUAD_CurrentVersionRun_3b48 {
  strings:
    $key_3b48 = { 68 27 [2] 4c 29 [2] 67 05 [2] 49 27 [2] 5d 3c [2] 52 26 [2] 4c 3b [2] 4e 3a [2] 55 3c [2] 49 3b [2] 55 14 }

  condition:
    any of them
}