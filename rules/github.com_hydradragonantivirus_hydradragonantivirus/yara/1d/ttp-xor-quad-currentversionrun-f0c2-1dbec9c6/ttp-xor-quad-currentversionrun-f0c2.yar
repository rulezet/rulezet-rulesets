rule TTP_XOR_QUAD_CurrentVersionRun_f0c2 {
  strings:
    $key_f0c2 = { a3 ad [2] 87 a3 [2] ac 8f [2] 82 ad [2] 96 b6 [2] 99 ac [2] 87 b1 [2] 85 b0 [2] 9e b6 [2] 82 b1 [2] 9e 9e }

  condition:
    any of them
}