rule TTP_XOR_QUAD_CurrentVersionRun_3dbe {
  strings:
    $key_3dbe = { 6e d1 [2] 4a df [2] 61 f3 [2] 4f d1 [2] 5b ca [2] 54 d0 [2] 4a cd [2] 48 cc [2] 53 ca [2] 4f cd [2] 53 e2 }

  condition:
    any of them
}