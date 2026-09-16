rule TTP_XOR_QUAD_CurrentVersionRun_cba4 {
  strings:
    $key_cba4 = { 98 cb [2] bc c5 [2] 97 e9 [2] b9 cb [2] ad d0 [2] a2 ca [2] bc d7 [2] be d6 [2] a5 d0 [2] b9 d7 [2] a5 f8 }

  condition:
    any of them
}