rule TTP_XOR_QUAD_CurrentVersionRun_f7c2 {
  strings:
    $key_f7c2 = { a4 ad [2] 80 a3 [2] ab 8f [2] 85 ad [2] 91 b6 [2] 9e ac [2] 80 b1 [2] 82 b0 [2] 99 b6 [2] 85 b1 [2] 99 9e }

  condition:
    any of them
}