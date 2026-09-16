rule TTP_XOR_QUAD_CurrentVersionRun_57c5 {
  strings:
    $key_57c5 = { 04 aa [2] 20 a4 [2] 0b 88 [2] 25 aa [2] 31 b1 [2] 3e ab [2] 20 b6 [2] 22 b7 [2] 39 b1 [2] 25 b6 [2] 39 99 }

  condition:
    any of them
}