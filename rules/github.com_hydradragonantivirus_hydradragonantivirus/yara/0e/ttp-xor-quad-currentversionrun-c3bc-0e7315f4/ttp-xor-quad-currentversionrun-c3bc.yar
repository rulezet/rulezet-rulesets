rule TTP_XOR_QUAD_CurrentVersionRun_c3bc {
  strings:
    $key_c3bc = { 90 d3 [2] b4 dd [2] 9f f1 [2] b1 d3 [2] a5 c8 [2] aa d2 [2] b4 cf [2] b6 ce [2] ad c8 [2] b1 cf [2] ad e0 }

  condition:
    any of them
}