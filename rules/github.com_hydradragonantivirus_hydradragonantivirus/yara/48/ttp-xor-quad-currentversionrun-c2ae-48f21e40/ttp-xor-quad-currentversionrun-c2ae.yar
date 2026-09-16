rule TTP_XOR_QUAD_CurrentVersionRun_c2ae {
  strings:
    $key_c2ae = { 91 c1 [2] b5 cf [2] 9e e3 [2] b0 c1 [2] a4 da [2] ab c0 [2] b5 dd [2] b7 dc [2] ac da [2] b0 dd [2] ac f2 }

  condition:
    any of them
}