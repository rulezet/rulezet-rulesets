rule TTP_XOR_QUAD_CurrentVersionRun_0420 {
  strings:
    $key_0420 = { 57 4f [2] 73 41 [2] 58 6d [2] 76 4f [2] 62 54 [2] 6d 4e [2] 73 53 [2] 71 52 [2] 6a 54 [2] 76 53 [2] 6a 7c }

  condition:
    any of them
}