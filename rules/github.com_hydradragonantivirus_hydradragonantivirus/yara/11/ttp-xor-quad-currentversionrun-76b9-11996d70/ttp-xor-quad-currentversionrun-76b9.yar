rule TTP_XOR_QUAD_CurrentVersionRun_76b9 {
  strings:
    $key_76b9 = { 25 d6 [2] 01 d8 [2] 2a f4 [2] 04 d6 [2] 10 cd [2] 1f d7 [2] 01 ca [2] 03 cb [2] 18 cd [2] 04 ca [2] 18 e5 }

  condition:
    any of them
}