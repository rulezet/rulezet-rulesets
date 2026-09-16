rule TTP_XOR_QUAD_CurrentVersionRun_65bf {
  strings:
    $key_65bf = { 36 d0 [2] 12 de [2] 39 f2 [2] 17 d0 [2] 03 cb [2] 0c d1 [2] 12 cc [2] 10 cd [2] 0b cb [2] 17 cc [2] 0b e3 }

  condition:
    any of them
}