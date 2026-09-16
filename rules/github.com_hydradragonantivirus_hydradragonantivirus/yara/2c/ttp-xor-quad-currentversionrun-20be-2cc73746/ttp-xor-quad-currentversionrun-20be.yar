rule TTP_XOR_QUAD_CurrentVersionRun_20be {
  strings:
    $key_20be = { 73 d1 [2] 57 df [2] 7c f3 [2] 52 d1 [2] 46 ca [2] 49 d0 [2] 57 cd [2] 55 cc [2] 4e ca [2] 52 cd [2] 4e e2 }

  condition:
    any of them
}