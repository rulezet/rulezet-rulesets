rule TTP_XOR_QUAD_CurrentVersionRun_debb {
  strings:
    $key_debb = { 8d d4 [2] a9 da [2] 82 f6 [2] ac d4 [2] b8 cf [2] b7 d5 [2] a9 c8 [2] ab c9 [2] b0 cf [2] ac c8 [2] b0 e7 }

  condition:
    any of them
}