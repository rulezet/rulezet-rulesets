rule TTP_XOR_QUAD_CurrentVersionRun_cfcc {
  strings:
    $key_cfcc = { 9c a3 [2] b8 ad [2] 93 81 [2] bd a3 [2] a9 b8 [2] a6 a2 [2] b8 bf [2] ba be [2] a1 b8 [2] bd bf [2] a1 90 }

  condition:
    any of them
}