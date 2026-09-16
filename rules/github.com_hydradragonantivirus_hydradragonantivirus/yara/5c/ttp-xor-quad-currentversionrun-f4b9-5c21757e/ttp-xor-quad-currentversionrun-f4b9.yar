rule TTP_XOR_QUAD_CurrentVersionRun_f4b9 {
  strings:
    $key_f4b9 = { a7 d6 [2] 83 d8 [2] a8 f4 [2] 86 d6 [2] 92 cd [2] 9d d7 [2] 83 ca [2] 81 cb [2] 9a cd [2] 86 ca [2] 9a e5 }

  condition:
    any of them
}