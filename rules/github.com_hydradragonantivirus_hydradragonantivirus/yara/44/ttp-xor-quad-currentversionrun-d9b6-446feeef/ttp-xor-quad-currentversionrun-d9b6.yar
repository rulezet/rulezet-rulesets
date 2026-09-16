rule TTP_XOR_QUAD_CurrentVersionRun_d9b6 {
  strings:
    $key_d9b6 = { 8a d9 [2] ae d7 [2] 85 fb [2] ab d9 [2] bf c2 [2] b0 d8 [2] ae c5 [2] ac c4 [2] b7 c2 [2] ab c5 [2] b7 ea }

  condition:
    any of them
}