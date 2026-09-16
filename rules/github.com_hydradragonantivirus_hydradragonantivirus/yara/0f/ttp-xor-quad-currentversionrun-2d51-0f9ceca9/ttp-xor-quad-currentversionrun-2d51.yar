rule TTP_XOR_QUAD_CurrentVersionRun_2d51 {
  strings:
    $key_2d51 = { 7e 3e [2] 5a 30 [2] 71 1c [2] 5f 3e [2] 4b 25 [2] 44 3f [2] 5a 22 [2] 58 23 [2] 43 25 [2] 5f 22 [2] 43 0d }

  condition:
    any of them
}