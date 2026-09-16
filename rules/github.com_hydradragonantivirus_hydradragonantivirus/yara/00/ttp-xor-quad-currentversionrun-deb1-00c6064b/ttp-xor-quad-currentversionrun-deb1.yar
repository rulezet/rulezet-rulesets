rule TTP_XOR_QUAD_CurrentVersionRun_deb1 {
  strings:
    $key_deb1 = { 8d de [2] a9 d0 [2] 82 fc [2] ac de [2] b8 c5 [2] b7 df [2] a9 c2 [2] ab c3 [2] b0 c5 [2] ac c2 [2] b0 ed }

  condition:
    any of them
}