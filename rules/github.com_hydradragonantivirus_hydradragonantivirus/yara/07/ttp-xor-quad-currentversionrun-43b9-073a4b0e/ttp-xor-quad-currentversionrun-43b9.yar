rule TTP_XOR_QUAD_CurrentVersionRun_43b9 {
  strings:
    $key_43b9 = { 10 d6 [2] 34 d8 [2] 1f f4 [2] 31 d6 [2] 25 cd [2] 2a d7 [2] 34 ca [2] 36 cb [2] 2d cd [2] 31 ca [2] 2d e5 }

  condition:
    any of them
}