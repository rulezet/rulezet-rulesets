rule TTP_XOR_QUAD_CurrentVersionRun_15be {
  strings:
    $key_15be = { 46 d1 [2] 62 df [2] 49 f3 [2] 67 d1 [2] 73 ca [2] 7c d0 [2] 62 cd [2] 60 cc [2] 7b ca [2] 67 cd [2] 7b e2 }

  condition:
    any of them
}