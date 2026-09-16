rule TTP_XOR_QUAD_CurrentVersionRun_cd8f {
  strings:
    $key_cd8f = { 9e e0 [2] ba ee [2] 91 c2 [2] bf e0 [2] ab fb [2] a4 e1 [2] ba fc [2] b8 fd [2] a3 fb [2] bf fc [2] a3 d3 }

  condition:
    any of them
}