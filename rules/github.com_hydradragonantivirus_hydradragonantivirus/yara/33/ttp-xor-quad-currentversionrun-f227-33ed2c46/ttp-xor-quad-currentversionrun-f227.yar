rule TTP_XOR_QUAD_CurrentVersionRun_f227 {
  strings:
    $key_f227 = { a1 48 [2] 85 46 [2] ae 6a [2] 80 48 [2] 94 53 [2] 9b 49 [2] 85 54 [2] 87 55 [2] 9c 53 [2] 80 54 [2] 9c 7b }

  condition:
    any of them
}