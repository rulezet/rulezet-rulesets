rule TTP_XOR_QUAD_CurrentVersionRun_3cf3 {
  strings:
    $key_3cf3 = { 6f 9c [2] 4b 92 [2] 60 be [2] 4e 9c [2] 5a 87 [2] 55 9d [2] 4b 80 [2] 49 81 [2] 52 87 [2] 4e 80 [2] 52 af }

  condition:
    any of them
}