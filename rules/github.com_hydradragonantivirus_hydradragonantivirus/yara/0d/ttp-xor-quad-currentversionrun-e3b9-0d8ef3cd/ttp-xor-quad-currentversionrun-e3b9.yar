rule TTP_XOR_QUAD_CurrentVersionRun_e3b9 {
  strings:
    $key_e3b9 = { b0 d6 [2] 94 d8 [2] bf f4 [2] 91 d6 [2] 85 cd [2] 8a d7 [2] 94 ca [2] 96 cb [2] 8d cd [2] 91 ca [2] 8d e5 }

  condition:
    any of them
}