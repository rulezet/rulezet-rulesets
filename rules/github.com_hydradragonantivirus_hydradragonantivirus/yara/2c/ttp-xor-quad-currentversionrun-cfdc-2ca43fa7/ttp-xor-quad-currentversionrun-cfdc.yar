rule TTP_XOR_QUAD_CurrentVersionRun_cfdc {
  strings:
    $key_cfdc = { 9c b3 [2] b8 bd [2] 93 91 [2] bd b3 [2] a9 a8 [2] a6 b2 [2] b8 af [2] ba ae [2] a1 a8 [2] bd af [2] a1 80 }

  condition:
    any of them
}