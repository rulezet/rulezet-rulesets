rule TTP_XOR_QUAD_CurrentVersionRun_26b9 {
  strings:
    $key_26b9 = { 75 d6 [2] 51 d8 [2] 7a f4 [2] 54 d6 [2] 40 cd [2] 4f d7 [2] 51 ca [2] 53 cb [2] 48 cd [2] 54 ca [2] 48 e5 }

  condition:
    any of them
}