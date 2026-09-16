rule TTP_XOR_QUAD_CurrentVersionRun_bb87 {
  strings:
    $key_bb87 = { e8 e8 [2] cc e6 [2] e7 ca [2] c9 e8 [2] dd f3 [2] d2 e9 [2] cc f4 [2] ce f5 [2] d5 f3 [2] c9 f4 [2] d5 db }

  condition:
    any of them
}