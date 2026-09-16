rule TTP_XOR_QUAD_CurrentVersionRun_ccb9 {
  strings:
    $key_ccb9 = { 9f d6 [2] bb d8 [2] 90 f4 [2] be d6 [2] aa cd [2] a5 d7 [2] bb ca [2] b9 cb [2] a2 cd [2] be ca [2] a2 e5 }

  condition:
    any of them
}