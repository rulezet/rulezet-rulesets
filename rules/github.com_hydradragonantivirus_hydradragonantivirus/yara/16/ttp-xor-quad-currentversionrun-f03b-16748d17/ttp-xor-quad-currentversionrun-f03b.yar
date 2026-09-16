rule TTP_XOR_QUAD_CurrentVersionRun_f03b {
  strings:
    $key_f03b = { a3 54 [2] 87 5a [2] ac 76 [2] 82 54 [2] 96 4f [2] 99 55 [2] 87 48 [2] 85 49 [2] 9e 4f [2] 82 48 [2] 9e 67 }

  condition:
    any of them
}