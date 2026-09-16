rule TTP_XOR_QUAD_CurrentVersionRun_16c5 {
  strings:
    $key_16c5 = { 45 aa [2] 61 a4 [2] 4a 88 [2] 64 aa [2] 70 b1 [2] 7f ab [2] 61 b6 [2] 63 b7 [2] 78 b1 [2] 64 b6 [2] 78 99 }

  condition:
    any of them
}