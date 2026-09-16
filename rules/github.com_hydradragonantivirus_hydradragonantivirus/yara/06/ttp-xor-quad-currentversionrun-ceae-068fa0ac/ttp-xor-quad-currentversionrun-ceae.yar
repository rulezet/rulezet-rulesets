rule TTP_XOR_QUAD_CurrentVersionRun_ceae {
  strings:
    $key_ceae = { 9d c1 [2] b9 cf [2] 92 e3 [2] bc c1 [2] a8 da [2] a7 c0 [2] b9 dd [2] bb dc [2] a0 da [2] bc dd [2] a0 f2 }

  condition:
    any of them
}