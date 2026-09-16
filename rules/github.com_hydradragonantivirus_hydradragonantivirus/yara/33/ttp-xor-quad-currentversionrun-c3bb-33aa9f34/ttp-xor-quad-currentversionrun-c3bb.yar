rule TTP_XOR_QUAD_CurrentVersionRun_c3bb {
  strings:
    $key_c3bb = { 90 d4 [2] b4 da [2] 9f f6 [2] b1 d4 [2] a5 cf [2] aa d5 [2] b4 c8 [2] b6 c9 [2] ad cf [2] b1 c8 [2] ad e7 }

  condition:
    any of them
}