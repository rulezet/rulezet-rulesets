rule TTP_XOR_QUAD_CurrentVersionRun_f7c5 {
  strings:
    $key_f7c5 = { a4 aa [2] 80 a4 [2] ab 88 [2] 85 aa [2] 91 b1 [2] 9e ab [2] 80 b6 [2] 82 b7 [2] 99 b1 [2] 85 b6 [2] 99 99 }

  condition:
    any of them
}