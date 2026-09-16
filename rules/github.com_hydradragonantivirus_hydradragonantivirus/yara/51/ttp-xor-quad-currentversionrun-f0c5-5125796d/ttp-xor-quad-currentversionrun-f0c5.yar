rule TTP_XOR_QUAD_CurrentVersionRun_f0c5 {
  strings:
    $key_f0c5 = { a3 aa [2] 87 a4 [2] ac 88 [2] 82 aa [2] 96 b1 [2] 99 ab [2] 87 b6 [2] 85 b7 [2] 9e b1 [2] 82 b6 [2] 9e 99 }

  condition:
    any of them
}