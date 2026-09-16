rule TTP_XOR_QUAD_CurrentVersionRun_1ebe {
  strings:
    $key_1ebe = { 4d d1 [2] 69 df [2] 42 f3 [2] 6c d1 [2] 78 ca [2] 77 d0 [2] 69 cd [2] 6b cc [2] 70 ca [2] 6c cd [2] 70 e2 }

  condition:
    any of them
}