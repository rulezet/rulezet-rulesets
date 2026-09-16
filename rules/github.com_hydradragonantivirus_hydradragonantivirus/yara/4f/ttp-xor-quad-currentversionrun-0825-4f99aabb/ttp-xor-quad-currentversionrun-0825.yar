rule TTP_XOR_QUAD_CurrentVersionRun_0825 {
  strings:
    $key_0825 = { 5b 4a [2] 7f 44 [2] 54 68 [2] 7a 4a [2] 6e 51 [2] 61 4b [2] 7f 56 [2] 7d 57 [2] 66 51 [2] 7a 56 [2] 66 79 }

  condition:
    any of them
}