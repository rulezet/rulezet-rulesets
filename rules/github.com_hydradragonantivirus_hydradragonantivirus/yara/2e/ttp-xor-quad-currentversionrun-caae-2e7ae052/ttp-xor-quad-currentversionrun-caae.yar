rule TTP_XOR_QUAD_CurrentVersionRun_caae {
  strings:
    $key_caae = { 99 c1 [2] bd cf [2] 96 e3 [2] b8 c1 [2] ac da [2] a3 c0 [2] bd dd [2] bf dc [2] a4 da [2] b8 dd [2] a4 f2 }

  condition:
    any of them
}