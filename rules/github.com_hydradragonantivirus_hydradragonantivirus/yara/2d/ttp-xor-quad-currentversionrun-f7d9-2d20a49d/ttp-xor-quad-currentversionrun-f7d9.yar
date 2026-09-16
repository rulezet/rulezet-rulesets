rule TTP_XOR_QUAD_CurrentVersionRun_f7d9 {
  strings:
    $key_f7d9 = { a4 b6 [2] 80 b8 [2] ab 94 [2] 85 b6 [2] 91 ad [2] 9e b7 [2] 80 aa [2] 82 ab [2] 99 ad [2] 85 aa [2] 99 85 }

  condition:
    any of them
}