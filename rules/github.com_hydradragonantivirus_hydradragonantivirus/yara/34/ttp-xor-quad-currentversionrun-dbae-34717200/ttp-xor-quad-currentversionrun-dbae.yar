rule TTP_XOR_QUAD_CurrentVersionRun_dbae {
  strings:
    $key_dbae = { 88 c1 [2] ac cf [2] 87 e3 [2] a9 c1 [2] bd da [2] b2 c0 [2] ac dd [2] ae dc [2] b5 da [2] a9 dd [2] b5 f2 }

  condition:
    any of them
}