rule TTP_XOR_QUAD_CurrentVersionRun_55ad {
  strings:
    $key_55ad = { 06 c2 [2] 22 cc [2] 09 e0 [2] 27 c2 [2] 33 d9 [2] 3c c3 [2] 22 de [2] 20 df [2] 3b d9 [2] 27 de [2] 3b f1 }

  condition:
    any of them
}