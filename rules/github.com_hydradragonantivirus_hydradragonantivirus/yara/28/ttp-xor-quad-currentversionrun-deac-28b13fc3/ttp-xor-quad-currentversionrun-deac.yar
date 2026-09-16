rule TTP_XOR_QUAD_CurrentVersionRun_deac {
  strings:
    $key_deac = { 8d c3 [2] a9 cd [2] 82 e1 [2] ac c3 [2] b8 d8 [2] b7 c2 [2] a9 df [2] ab de [2] b0 d8 [2] ac df [2] b0 f0 }

  condition:
    any of them
}