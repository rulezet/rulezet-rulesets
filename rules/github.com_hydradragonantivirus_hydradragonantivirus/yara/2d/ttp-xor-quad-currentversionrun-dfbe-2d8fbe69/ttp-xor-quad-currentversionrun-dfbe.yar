rule TTP_XOR_QUAD_CurrentVersionRun_dfbe {
  strings:
    $key_dfbe = { 8c d1 [2] a8 df [2] 83 f3 [2] ad d1 [2] b9 ca [2] b6 d0 [2] a8 cd [2] aa cc [2] b1 ca [2] ad cd [2] b1 e2 }

  condition:
    any of them
}