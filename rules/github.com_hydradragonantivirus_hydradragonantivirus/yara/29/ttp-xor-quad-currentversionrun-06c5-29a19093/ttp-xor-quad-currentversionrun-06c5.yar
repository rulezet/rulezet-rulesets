rule TTP_XOR_QUAD_CurrentVersionRun_06c5 {
  strings:
    $key_06c5 = { 55 aa [2] 71 a4 [2] 5a 88 [2] 74 aa [2] 60 b1 [2] 6f ab [2] 71 b6 [2] 73 b7 [2] 68 b1 [2] 74 b6 [2] 68 99 }

  condition:
    any of them
}