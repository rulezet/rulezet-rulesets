rule TTP_XOR_QUAD_CurrentVersionRun_5dbe {
  strings:
    $key_5dbe = { 0e d1 [2] 2a df [2] 01 f3 [2] 2f d1 [2] 3b ca [2] 34 d0 [2] 2a cd [2] 28 cc [2] 33 ca [2] 2f cd [2] 33 e2 }

  condition:
    any of them
}