rule TTP_XOR_QUAD_CurrentVersionRun_ec90 {
  strings:
    $key_ec90 = { bf ff [2] 9b f1 [2] b0 dd [2] 9e ff [2] 8a e4 [2] 85 fe [2] 9b e3 [2] 99 e2 [2] 82 e4 [2] 9e e3 [2] 82 cc }

  condition:
    any of them
}