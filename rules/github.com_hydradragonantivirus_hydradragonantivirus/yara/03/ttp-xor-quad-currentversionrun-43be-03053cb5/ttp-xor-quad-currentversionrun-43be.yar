rule TTP_XOR_QUAD_CurrentVersionRun_43be {
  strings:
    $key_43be = { 10 d1 [2] 34 df [2] 1f f3 [2] 31 d1 [2] 25 ca [2] 2a d0 [2] 34 cd [2] 36 cc [2] 2d ca [2] 31 cd [2] 2d e2 }

  condition:
    any of them
}