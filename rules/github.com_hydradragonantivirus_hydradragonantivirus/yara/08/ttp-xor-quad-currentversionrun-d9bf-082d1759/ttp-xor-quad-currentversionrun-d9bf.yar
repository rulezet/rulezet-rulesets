rule TTP_XOR_QUAD_CurrentVersionRun_d9bf {
  strings:
    $key_d9bf = { 8a d0 [2] ae de [2] 85 f2 [2] ab d0 [2] bf cb [2] b0 d1 [2] ae cc [2] ac cd [2] b7 cb [2] ab cc [2] b7 e3 }

  condition:
    any of them
}