rule TTP_XOR_QUAD_CurrentVersionRun_f279 {
  strings:
    $key_f279 = { a1 16 [2] 85 18 [2] ae 34 [2] 80 16 [2] 94 0d [2] 9b 17 [2] 85 0a [2] 87 0b [2] 9c 0d [2] 80 0a [2] 9c 25 }

  condition:
    any of them
}