rule TTP_XOR_QUAD_CurrentVersionRun_0c51 {
  strings:
    $key_0c51 = { 5f 3e [2] 7b 30 [2] 50 1c [2] 7e 3e [2] 6a 25 [2] 65 3f [2] 7b 22 [2] 79 23 [2] 62 25 [2] 7e 22 [2] 62 0d }

  condition:
    any of them
}