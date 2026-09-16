rule TTP_XOR_QUAD_CurrentVersionRun_daae {
  strings:
    $key_daae = { 89 c1 [2] ad cf [2] 86 e3 [2] a8 c1 [2] bc da [2] b3 c0 [2] ad dd [2] af dc [2] b4 da [2] a8 dd [2] b4 f2 }

  condition:
    any of them
}