rule TTP_XOR_QUAD_CurrentVersionRun_f217 {
  strings:
    $key_f217 = { a1 78 [2] 85 76 [2] ae 5a [2] 80 78 [2] 94 63 [2] 9b 79 [2] 85 64 [2] 87 65 [2] 9c 63 [2] 80 64 [2] 9c 4b }

  condition:
    any of them
}