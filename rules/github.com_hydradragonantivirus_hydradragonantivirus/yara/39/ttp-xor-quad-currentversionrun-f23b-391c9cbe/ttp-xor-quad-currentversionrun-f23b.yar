rule TTP_XOR_QUAD_CurrentVersionRun_f23b {
  strings:
    $key_f23b = { a1 54 [2] 85 5a [2] ae 76 [2] 80 54 [2] 94 4f [2] 9b 55 [2] 85 48 [2] 87 49 [2] 9c 4f [2] 80 48 [2] 9c 67 }

  condition:
    any of them
}