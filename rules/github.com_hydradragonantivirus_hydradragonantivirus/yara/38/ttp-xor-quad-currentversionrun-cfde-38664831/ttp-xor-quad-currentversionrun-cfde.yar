rule TTP_XOR_QUAD_CurrentVersionRun_cfde {
  strings:
    $key_cfde = { 9c b1 [2] b8 bf [2] 93 93 [2] bd b1 [2] a9 aa [2] a6 b0 [2] b8 ad [2] ba ac [2] a1 aa [2] bd ad [2] a1 82 }

  condition:
    any of them
}