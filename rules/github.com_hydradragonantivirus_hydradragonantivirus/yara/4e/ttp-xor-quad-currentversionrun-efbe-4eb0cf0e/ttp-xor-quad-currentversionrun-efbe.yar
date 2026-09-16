rule TTP_XOR_QUAD_CurrentVersionRun_efbe {
  strings:
    $key_efbe = { bc d1 [2] 98 df [2] b3 f3 [2] 9d d1 [2] 89 ca [2] 86 d0 [2] 98 cd [2] 9a cc [2] 81 ca [2] 9d cd [2] 81 e2 }

  condition:
    any of them
}