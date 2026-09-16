rule TTP_XOR_QUAD_CurrentVersionRun_d580 {
  strings:
    $key_d580 = { 86 ef [2] a2 e1 [2] 89 cd [2] a7 ef [2] b3 f4 [2] bc ee [2] a2 f3 [2] a0 f2 [2] bb f4 [2] a7 f3 [2] bb dc }

  condition:
    any of them
}