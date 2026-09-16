rule TTP_XOR_QUAD_CurrentVersionRun_b4cb {
  strings:
    $key_b4cb = { e7 a4 [2] c3 aa [2] e8 86 [2] c6 a4 [2] d2 bf [2] dd a5 [2] c3 b8 [2] c1 b9 [2] da bf [2] c6 b8 [2] da 97 }

  condition:
    any of them
}