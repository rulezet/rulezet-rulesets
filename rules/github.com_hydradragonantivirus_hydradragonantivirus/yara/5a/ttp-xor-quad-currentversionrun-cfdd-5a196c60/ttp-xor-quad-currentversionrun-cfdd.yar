rule TTP_XOR_QUAD_CurrentVersionRun_cfdd {
  strings:
    $key_cfdd = { 9c b2 [2] b8 bc [2] 93 90 [2] bd b2 [2] a9 a9 [2] a6 b3 [2] b8 ae [2] ba af [2] a1 a9 [2] bd ae [2] a1 81 }

  condition:
    any of them
}