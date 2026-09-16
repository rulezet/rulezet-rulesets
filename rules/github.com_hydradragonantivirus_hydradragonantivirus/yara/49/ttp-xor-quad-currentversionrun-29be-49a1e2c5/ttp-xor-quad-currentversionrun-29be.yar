rule TTP_XOR_QUAD_CurrentVersionRun_29be {
  strings:
    $key_29be = { 7a d1 [2] 5e df [2] 75 f3 [2] 5b d1 [2] 4f ca [2] 40 d0 [2] 5e cd [2] 5c cc [2] 47 ca [2] 5b cd [2] 47 e2 }

  condition:
    any of them
}