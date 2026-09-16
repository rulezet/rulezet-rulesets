rule TTP_XOR_QUAD_CurrentVersionRun_2bbe {
  strings:
    $key_2bbe = { 78 d1 [2] 5c df [2] 77 f3 [2] 59 d1 [2] 4d ca [2] 42 d0 [2] 5c cd [2] 5e cc [2] 45 ca [2] 59 cd [2] 45 e2 }

  condition:
    any of them
}