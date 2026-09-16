rule TTP_XOR_QUAD_CurrentVersionRun_8f87 {
  strings:
    $key_8f87 = { dc e8 [2] f8 e6 [2] d3 ca [2] fd e8 [2] e9 f3 [2] e6 e9 [2] f8 f4 [2] fa f5 [2] e1 f3 [2] fd f4 [2] e1 db }

  condition:
    any of them
}