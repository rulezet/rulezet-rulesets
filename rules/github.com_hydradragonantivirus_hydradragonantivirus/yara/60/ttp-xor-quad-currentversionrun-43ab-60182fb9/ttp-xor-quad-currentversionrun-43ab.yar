rule TTP_XOR_QUAD_CurrentVersionRun_43ab {
  strings:
    $key_43ab = { 10 c4 [2] 34 ca [2] 1f e6 [2] 31 c4 [2] 25 df [2] 2a c5 [2] 34 d8 [2] 36 d9 [2] 2d df [2] 31 d8 [2] 2d f7 }

  condition:
    any of them
}