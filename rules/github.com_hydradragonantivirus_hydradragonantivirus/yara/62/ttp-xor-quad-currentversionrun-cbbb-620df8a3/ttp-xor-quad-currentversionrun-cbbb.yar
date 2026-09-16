rule TTP_XOR_QUAD_CurrentVersionRun_cbbb {
  strings:
    $key_cbbb = { 98 d4 [2] bc da [2] 97 f6 [2] b9 d4 [2] ad cf [2] a2 d5 [2] bc c8 [2] be c9 [2] a5 cf [2] b9 c8 [2] a5 e7 }

  condition:
    any of them
}