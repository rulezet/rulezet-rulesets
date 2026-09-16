rule TTP_XOR_QUAD_CurrentVersionRun_0949 {
  strings:
    $key_0949 = { 5a 26 [2] 7e 28 [2] 55 04 [2] 7b 26 [2] 6f 3d [2] 60 27 [2] 7e 3a [2] 7c 3b [2] 67 3d [2] 7b 3a [2] 67 15 }

  condition:
    any of them
}