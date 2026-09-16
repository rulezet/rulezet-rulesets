rule TTP_XOR_QUAD_CurrentVersionRun_2ef3 {
  strings:
    $key_2ef3 = { 7d 9c [2] 59 92 [2] 72 be [2] 5c 9c [2] 48 87 [2] 47 9d [2] 59 80 [2] 5b 81 [2] 40 87 [2] 5c 80 [2] 40 af }

  condition:
    any of them
}