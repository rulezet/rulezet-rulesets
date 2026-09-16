rule TTP_XOR_QUAD_CurrentVersionRun_16a4 {
  strings:
    $key_16a4 = { 45 cb [2] 61 c5 [2] 4a e9 [2] 64 cb [2] 70 d0 [2] 7f ca [2] 61 d7 [2] 63 d6 [2] 78 d0 [2] 64 d7 [2] 78 f8 }

  condition:
    any of them
}