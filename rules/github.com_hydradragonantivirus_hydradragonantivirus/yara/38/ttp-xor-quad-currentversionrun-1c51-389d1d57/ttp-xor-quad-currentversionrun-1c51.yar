rule TTP_XOR_QUAD_CurrentVersionRun_1c51 {
  strings:
    $key_1c51 = { 4f 3e [2] 6b 30 [2] 40 1c [2] 6e 3e [2] 7a 25 [2] 75 3f [2] 6b 22 [2] 69 23 [2] 72 25 [2] 6e 22 [2] 72 0d }

  condition:
    any of them
}