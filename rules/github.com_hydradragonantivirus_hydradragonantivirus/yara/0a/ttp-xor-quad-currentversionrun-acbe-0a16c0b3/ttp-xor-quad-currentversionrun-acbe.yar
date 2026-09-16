rule TTP_XOR_QUAD_CurrentVersionRun_acbe {
  strings:
    $key_acbe = { ff d1 [2] db df [2] f0 f3 [2] de d1 [2] ca ca [2] c5 d0 [2] db cd [2] d9 cc [2] c2 ca [2] de cd [2] c2 e2 }

  condition:
    any of them
}