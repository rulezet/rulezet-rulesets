rule TTP_XOR_QUAD_CurrentVersionRun_cda1 {
  strings:
    $key_cda1 = { 9e ce [2] ba c0 [2] 91 ec [2] bf ce [2] ab d5 [2] a4 cf [2] ba d2 [2] b8 d3 [2] a3 d5 [2] bf d2 [2] a3 fd }

  condition:
    any of them
}