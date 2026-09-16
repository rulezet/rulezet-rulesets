rule TTP_XOR_QUAD_CurrentVersionRun_d3af {
  strings:
    $key_d3af = { 80 c0 [2] a4 ce [2] 8f e2 [2] a1 c0 [2] b5 db [2] ba c1 [2] a4 dc [2] a6 dd [2] bd db [2] a1 dc [2] bd f3 }

  condition:
    any of them
}