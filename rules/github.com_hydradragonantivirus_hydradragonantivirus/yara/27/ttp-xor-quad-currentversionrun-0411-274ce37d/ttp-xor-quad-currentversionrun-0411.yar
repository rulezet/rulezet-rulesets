rule TTP_XOR_QUAD_CurrentVersionRun_0411 {
  strings:
    $key_0411 = { 57 7e [2] 73 70 [2] 58 5c [2] 76 7e [2] 62 65 [2] 6d 7f [2] 73 62 [2] 71 63 [2] 6a 65 [2] 76 62 [2] 6a 4d }

  condition:
    any of them
}