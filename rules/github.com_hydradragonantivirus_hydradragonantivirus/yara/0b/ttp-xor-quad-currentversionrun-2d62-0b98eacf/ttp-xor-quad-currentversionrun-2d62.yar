rule TTP_XOR_QUAD_CurrentVersionRun_2d62 {
  strings:
    $key_2d62 = { 7e 0d [2] 5a 03 [2] 71 2f [2] 5f 0d [2] 4b 16 [2] 44 0c [2] 5a 11 [2] 58 10 [2] 43 16 [2] 5f 11 [2] 43 3e }

  condition:
    any of them
}