rule TTP_XOR_QUAD_CurrentVersionRun_0663 {
  strings:
    $key_0663 = { 55 0c [2] 71 02 [2] 5a 2e [2] 74 0c [2] 60 17 [2] 6f 0d [2] 71 10 [2] 73 11 [2] 68 17 [2] 74 10 [2] 68 3f }

  condition:
    any of them
}