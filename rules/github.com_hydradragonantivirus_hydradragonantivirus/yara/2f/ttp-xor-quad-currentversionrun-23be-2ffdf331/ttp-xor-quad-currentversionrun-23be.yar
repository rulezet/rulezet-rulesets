rule TTP_XOR_QUAD_CurrentVersionRun_23be {
  strings:
    $key_23be = { 70 d1 [2] 54 df [2] 7f f3 [2] 51 d1 [2] 45 ca [2] 4a d0 [2] 54 cd [2] 56 cc [2] 4d ca [2] 51 cd [2] 4d e2 }

  condition:
    any of them
}