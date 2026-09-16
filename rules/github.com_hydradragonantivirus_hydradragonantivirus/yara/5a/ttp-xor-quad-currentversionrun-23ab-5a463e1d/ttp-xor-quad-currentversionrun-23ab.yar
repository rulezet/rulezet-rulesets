rule TTP_XOR_QUAD_CurrentVersionRun_23ab {
  strings:
    $key_23ab = { 70 c4 [2] 54 ca [2] 7f e6 [2] 51 c4 [2] 45 df [2] 4a c5 [2] 54 d8 [2] 56 d9 [2] 4d df [2] 51 d8 [2] 4d f7 }

  condition:
    any of them
}