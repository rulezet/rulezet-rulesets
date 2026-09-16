rule TTP_XOR_QUAD_CurrentVersionRun_5fbe {
  strings:
    $key_5fbe = { 0c d1 [2] 28 df [2] 03 f3 [2] 2d d1 [2] 39 ca [2] 36 d0 [2] 28 cd [2] 2a cc [2] 31 ca [2] 2d cd [2] 31 e2 }

  condition:
    any of them
}