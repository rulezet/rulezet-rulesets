rule TTP_XOR_QUAD_CurrentVersionRun_0640 {
  strings:
    $key_0640 = { 55 2f [2] 71 21 [2] 5a 0d [2] 74 2f [2] 60 34 [2] 6f 2e [2] 71 33 [2] 73 32 [2] 68 34 [2] 74 33 [2] 68 1c }

  condition:
    any of them
}