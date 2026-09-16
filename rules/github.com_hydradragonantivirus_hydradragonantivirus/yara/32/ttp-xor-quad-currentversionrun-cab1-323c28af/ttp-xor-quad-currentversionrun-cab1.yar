rule TTP_XOR_QUAD_CurrentVersionRun_cab1 {
  strings:
    $key_cab1 = { 99 de [2] bd d0 [2] 96 fc [2] b8 de [2] ac c5 [2] a3 df [2] bd c2 [2] bf c3 [2] a4 c5 [2] b8 c2 [2] a4 ed }

  condition:
    any of them
}