rule TTP_XOR_QUAD_CurrentVersionRun_3bbe {
  strings:
    $key_3bbe = { 68 d1 [2] 4c df [2] 67 f3 [2] 49 d1 [2] 5d ca [2] 52 d0 [2] 4c cd [2] 4e cc [2] 55 ca [2] 49 cd [2] 55 e2 }

  condition:
    any of them
}