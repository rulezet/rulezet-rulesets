rule TTP_XOR_QUAD_CurrentVersionRun_07be {
  strings:
    $key_07be = { 54 d1 [2] 70 df [2] 5b f3 [2] 75 d1 [2] 61 ca [2] 6e d0 [2] 70 cd [2] 72 cc [2] 69 ca [2] 75 cd [2] 69 e2 }

  condition:
    any of them
}