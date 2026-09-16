rule TTP_XOR_QUAD_CurrentVersionRun_01c5 {
  strings:
    $key_01c5 = { 52 aa [2] 76 a4 [2] 5d 88 [2] 73 aa [2] 67 b1 [2] 68 ab [2] 76 b6 [2] 74 b7 [2] 6f b1 [2] 73 b6 [2] 6f 99 }

  condition:
    any of them
}