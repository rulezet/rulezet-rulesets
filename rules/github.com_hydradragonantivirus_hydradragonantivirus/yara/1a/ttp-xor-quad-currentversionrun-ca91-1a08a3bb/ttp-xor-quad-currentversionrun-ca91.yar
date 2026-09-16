rule TTP_XOR_QUAD_CurrentVersionRun_ca91 {
  strings:
    $key_ca91 = { 99 fe [2] bd f0 [2] 96 dc [2] b8 fe [2] ac e5 [2] a3 ff [2] bd e2 [2] bf e3 [2] a4 e5 [2] b8 e2 [2] a4 cd }

  condition:
    any of them
}