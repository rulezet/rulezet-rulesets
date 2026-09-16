rule TTP_XOR_QUAD_CurrentVersionRun_0ebe {
  strings:
    $key_0ebe = { 5d d1 [2] 79 df [2] 52 f3 [2] 7c d1 [2] 68 ca [2] 67 d0 [2] 79 cd [2] 7b cc [2] 60 ca [2] 7c cd [2] 60 e2 }

  condition:
    any of them
}