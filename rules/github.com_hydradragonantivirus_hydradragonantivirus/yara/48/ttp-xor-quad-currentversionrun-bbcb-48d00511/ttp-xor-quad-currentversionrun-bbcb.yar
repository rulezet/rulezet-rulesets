rule TTP_XOR_QUAD_CurrentVersionRun_bbcb {
  strings:
    $key_bbcb = { e8 a4 [2] cc aa [2] e7 86 [2] c9 a4 [2] dd bf [2] d2 a5 [2] cc b8 [2] ce b9 [2] d5 bf [2] c9 b8 [2] d5 97 }

  condition:
    any of them
}