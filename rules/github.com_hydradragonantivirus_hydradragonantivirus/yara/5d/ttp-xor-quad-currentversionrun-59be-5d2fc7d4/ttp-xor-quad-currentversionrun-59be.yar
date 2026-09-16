rule TTP_XOR_QUAD_CurrentVersionRun_59be {
  strings:
    $key_59be = { 0a d1 [2] 2e df [2] 05 f3 [2] 2b d1 [2] 3f ca [2] 30 d0 [2] 2e cd [2] 2c cc [2] 37 ca [2] 2b cd [2] 37 e2 }

  condition:
    any of them
}