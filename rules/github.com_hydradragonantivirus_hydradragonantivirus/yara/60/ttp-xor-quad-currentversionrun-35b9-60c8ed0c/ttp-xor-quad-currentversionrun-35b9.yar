rule TTP_XOR_QUAD_CurrentVersionRun_35b9 {
  strings:
    $key_35b9 = { 66 d6 [2] 42 d8 [2] 69 f4 [2] 47 d6 [2] 53 cd [2] 5c d7 [2] 42 ca [2] 40 cb [2] 5b cd [2] 47 ca [2] 5b e5 }

  condition:
    any of them
}