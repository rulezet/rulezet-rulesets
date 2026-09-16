rule TTP_XOR_QUAD_CurrentVersionRun_37c5 {
  strings:
    $key_37c5 = { 64 aa [2] 40 a4 [2] 6b 88 [2] 45 aa [2] 51 b1 [2] 5e ab [2] 40 b6 [2] 42 b7 [2] 59 b1 [2] 45 b6 [2] 59 99 }

  condition:
    any of them
}