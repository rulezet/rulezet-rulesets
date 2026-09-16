rule TTP_XOR_QUAD_CurrentVersionRun_d9ba {
  strings:
    $key_d9ba = { 8a d5 [2] ae db [2] 85 f7 [2] ab d5 [2] bf ce [2] b0 d4 [2] ae c9 [2] ac c8 [2] b7 ce [2] ab c9 [2] b7 e6 }

  condition:
    any of them
}