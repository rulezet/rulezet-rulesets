rule TTP_XOR_QUAD_CurrentVersionRun_6bbe {
  strings:
    $key_6bbe = { 38 d1 [2] 1c df [2] 37 f3 [2] 19 d1 [2] 0d ca [2] 02 d0 [2] 1c cd [2] 1e cc [2] 05 ca [2] 19 cd [2] 05 e2 }

  condition:
    any of them
}