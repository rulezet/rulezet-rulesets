rule TTP_XOR_QUAD_CurrentVersionRun_7fbe {
  strings:
    $key_7fbe = { 2c d1 [2] 08 df [2] 23 f3 [2] 0d d1 [2] 19 ca [2] 16 d0 [2] 08 cd [2] 0a cc [2] 11 ca [2] 0d cd [2] 11 e2 }

  condition:
    any of them
}