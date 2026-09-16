rule TTP_XOR_QUAD_CurrentVersionRun_1c21 {
  strings:
    $key_1c21 = { 4f 4e [2] 6b 40 [2] 40 6c [2] 6e 4e [2] 7a 55 [2] 75 4f [2] 6b 52 [2] 69 53 [2] 72 55 [2] 6e 52 [2] 72 7d }

  condition:
    any of them
}