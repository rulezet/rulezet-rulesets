rule TTP_XOR_QUAD_CurrentVersionRun_cebe {
  strings:
    $key_cebe = { 9d d1 [2] b9 df [2] 92 f3 [2] bc d1 [2] a8 ca [2] a7 d0 [2] b9 cd [2] bb cc [2] a0 ca [2] bc cd [2] a0 e2 }

  condition:
    any of them
}