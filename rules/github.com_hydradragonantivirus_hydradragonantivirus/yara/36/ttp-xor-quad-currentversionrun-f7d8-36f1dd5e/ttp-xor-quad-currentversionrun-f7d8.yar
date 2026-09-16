rule TTP_XOR_QUAD_CurrentVersionRun_f7d8 {
  strings:
    $key_f7d8 = { a4 b7 [2] 80 b9 [2] ab 95 [2] 85 b7 [2] 91 ac [2] 9e b6 [2] 80 ab [2] 82 aa [2] 99 ac [2] 85 ab [2] 99 84 }

  condition:
    any of them
}