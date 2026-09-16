rule TTP_XOR_QUAD_CurrentVersionRun_1751 {
  strings:
    $key_1751 = { 44 3e [2] 60 30 [2] 4b 1c [2] 65 3e [2] 71 25 [2] 7e 3f [2] 60 22 [2] 62 23 [2] 79 25 [2] 65 22 [2] 79 0d }

  condition:
    any of them
}