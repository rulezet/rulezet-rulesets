rule TTP_XOR_QUAD_CurrentVersionRun_1521 {
  strings:
    $key_1521 = { 46 4e [2] 62 40 [2] 49 6c [2] 67 4e [2] 73 55 [2] 7c 4f [2] 62 52 [2] 60 53 [2] 7b 55 [2] 67 52 [2] 7b 7d }

  condition:
    any of them
}