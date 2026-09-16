rule TTP_XOR_QUAD_CurrentVersionRun_cbbd {
  strings:
    $key_cbbd = { 98 d2 [2] bc dc [2] 97 f0 [2] b9 d2 [2] ad c9 [2] a2 d3 [2] bc ce [2] be cf [2] a5 c9 [2] b9 ce [2] a5 e1 }

  condition:
    any of them
}