rule TTP_XOR_QUAD_CurrentVersionRun_16b9 {
  strings:
    $key_16b9 = { 45 d6 [2] 61 d8 [2] 4a f4 [2] 64 d6 [2] 70 cd [2] 7f d7 [2] 61 ca [2] 63 cb [2] 78 cd [2] 64 ca [2] 78 e5 }

  condition:
    any of them
}