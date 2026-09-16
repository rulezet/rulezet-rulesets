rule TTP_XOR_QUAD_CurrentVersionRun_46be {
  strings:
    $key_46be = { 15 d1 [2] 31 df [2] 1a f3 [2] 34 d1 [2] 20 ca [2] 2f d0 [2] 31 cd [2] 33 cc [2] 28 ca [2] 34 cd [2] 28 e2 }

  condition:
    any of them
}