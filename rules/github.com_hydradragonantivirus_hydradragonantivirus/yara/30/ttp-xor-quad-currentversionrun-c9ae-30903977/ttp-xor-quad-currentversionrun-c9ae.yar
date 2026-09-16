rule TTP_XOR_QUAD_CurrentVersionRun_c9ae {
  strings:
    $key_c9ae = { 9a c1 [2] be cf [2] 95 e3 [2] bb c1 [2] af da [2] a0 c0 [2] be dd [2] bc dc [2] a7 da [2] bb dd [2] a7 f2 }

  condition:
    any of them
}