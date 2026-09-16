rule TTP_XOR_QUAD_CurrentVersionRun_0c21 {
  strings:
    $key_0c21 = { 5f 4e [2] 7b 40 [2] 50 6c [2] 7e 4e [2] 6a 55 [2] 65 4f [2] 7b 52 [2] 79 53 [2] 62 55 [2] 7e 52 [2] 62 7d }

  condition:
    any of them
}