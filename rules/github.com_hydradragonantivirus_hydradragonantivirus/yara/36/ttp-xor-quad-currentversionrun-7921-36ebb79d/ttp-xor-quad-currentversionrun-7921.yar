rule TTP_XOR_QUAD_CurrentVersionRun_7921 {
  strings:
    $key_7921 = { 2a 4e [2] 0e 40 [2] 25 6c [2] 0b 4e [2] 1f 55 [2] 10 4f [2] 0e 52 [2] 0c 53 [2] 17 55 [2] 0b 52 [2] 17 7d }

  condition:
    any of them
}