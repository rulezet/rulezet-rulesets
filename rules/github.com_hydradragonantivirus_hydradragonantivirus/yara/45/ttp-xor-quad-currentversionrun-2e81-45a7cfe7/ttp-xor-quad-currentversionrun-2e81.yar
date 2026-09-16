rule TTP_XOR_QUAD_CurrentVersionRun_2e81 {
  strings:
    $key_2e81 = { 7d ee [2] 59 e0 [2] 72 cc [2] 5c ee [2] 48 f5 [2] 47 ef [2] 59 f2 [2] 5b f3 [2] 40 f5 [2] 5c f2 [2] 40 dd }

  condition:
    any of them
}