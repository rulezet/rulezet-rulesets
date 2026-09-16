rule TTP_XOR_QUAD_CurrentVersionRun_d2be {
  strings:
    $key_d2be = { 81 d1 [2] a5 df [2] 8e f3 [2] a0 d1 [2] b4 ca [2] bb d0 [2] a5 cd [2] a7 cc [2] bc ca [2] a0 cd [2] bc e2 }

  condition:
    any of them
}