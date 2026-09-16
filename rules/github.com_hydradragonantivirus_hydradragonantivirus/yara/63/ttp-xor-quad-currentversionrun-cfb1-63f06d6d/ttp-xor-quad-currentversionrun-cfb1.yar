rule TTP_XOR_QUAD_CurrentVersionRun_cfb1 {
  strings:
    $key_cfb1 = { 9c de [2] b8 d0 [2] 93 fc [2] bd de [2] a9 c5 [2] a6 df [2] b8 c2 [2] ba c3 [2] a1 c5 [2] bd c2 [2] a1 ed }

  condition:
    any of them
}