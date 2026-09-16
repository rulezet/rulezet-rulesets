rule TTP_XOR_QUAD_CurrentVersionRun_fedc {
  strings:
    $key_fedc = { ad b3 [2] 89 bd [2] a2 91 [2] 8c b3 [2] 98 a8 [2] 97 b2 [2] 89 af [2] 8b ae [2] 90 a8 [2] 8c af [2] 90 80 }

  condition:
    any of them
}