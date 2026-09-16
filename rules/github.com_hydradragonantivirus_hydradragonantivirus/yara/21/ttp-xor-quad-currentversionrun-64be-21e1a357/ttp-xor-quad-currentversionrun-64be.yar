rule TTP_XOR_QUAD_CurrentVersionRun_64be {
  strings:
    $key_64be = { 37 d1 [2] 13 df [2] 38 f3 [2] 16 d1 [2] 02 ca [2] 0d d0 [2] 13 cd [2] 11 cc [2] 0a ca [2] 16 cd [2] 0a e2 }

  condition:
    any of them
}