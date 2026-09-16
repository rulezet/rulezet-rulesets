rule TTP_XOR_QUAD_CurrentVersionRun_dbbe {
  strings:
    $key_dbbe = { 88 d1 [2] ac df [2] 87 f3 [2] a9 d1 [2] bd ca [2] b2 d0 [2] ac cd [2] ae cc [2] b5 ca [2] a9 cd [2] b5 e2 }

  condition:
    any of them
}