rule TTP_XOR_QUAD_CurrentVersionRun_73c5 {
  strings:
    $key_73c5 = { 20 aa [2] 04 a4 [2] 2f 88 [2] 01 aa [2] 15 b1 [2] 1a ab [2] 04 b6 [2] 06 b7 [2] 1d b1 [2] 01 b6 [2] 1d 99 }

  condition:
    any of them
}