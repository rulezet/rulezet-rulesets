rule TTP_XOR_QUAD_CurrentVersionRun_d39d {
  strings:
    $key_d39d = { 80 f2 [2] a4 fc [2] 8f d0 [2] a1 f2 [2] b5 e9 [2] ba f3 [2] a4 ee [2] a6 ef [2] bd e9 [2] a1 ee [2] bd c1 }

  condition:
    any of them
}