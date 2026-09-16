rule TTP_XOR_QUAD_CurrentVersionRun_eeb2 {
  strings:
    $key_eeb2 = { bd dd [2] 99 d3 [2] b2 ff [2] 9c dd [2] 88 c6 [2] 87 dc [2] 99 c1 [2] 9b c0 [2] 80 c6 [2] 9c c1 [2] 80 ee }

  condition:
    any of them
}