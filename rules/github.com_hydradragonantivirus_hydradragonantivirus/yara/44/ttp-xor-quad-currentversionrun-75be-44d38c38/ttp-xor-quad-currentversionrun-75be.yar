rule TTP_XOR_QUAD_CurrentVersionRun_75be {
  strings:
    $key_75be = { 26 d1 [2] 02 df [2] 29 f3 [2] 07 d1 [2] 13 ca [2] 1c d0 [2] 02 cd [2] 00 cc [2] 1b ca [2] 07 cd [2] 1b e2 }

  condition:
    any of them
}