rule TTP_XOR_QUAD_CurrentVersionRun_62bf {
  strings:
    $key_62bf = { 31 d0 [2] 15 de [2] 3e f2 [2] 10 d0 [2] 04 cb [2] 0b d1 [2] 15 cc [2] 17 cd [2] 0c cb [2] 10 cc [2] 0c e3 }

  condition:
    any of them
}