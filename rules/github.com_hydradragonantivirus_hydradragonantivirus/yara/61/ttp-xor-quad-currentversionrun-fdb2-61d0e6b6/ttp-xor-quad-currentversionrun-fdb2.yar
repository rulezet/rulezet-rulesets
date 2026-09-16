rule TTP_XOR_QUAD_CurrentVersionRun_fdb2 {
  strings:
    $key_fdb2 = { ae dd [2] 8a d3 [2] a1 ff [2] 8f dd [2] 9b c6 [2] 94 dc [2] 8a c1 [2] 88 c0 [2] 93 c6 [2] 8f c1 [2] 93 ee }

  condition:
    any of them
}