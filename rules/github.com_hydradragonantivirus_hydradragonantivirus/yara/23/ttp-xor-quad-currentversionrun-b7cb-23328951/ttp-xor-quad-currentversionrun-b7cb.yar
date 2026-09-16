rule TTP_XOR_QUAD_CurrentVersionRun_b7cb {
  strings:
    $key_b7cb = { e4 a4 [2] c0 aa [2] eb 86 [2] c5 a4 [2] d1 bf [2] de a5 [2] c0 b8 [2] c2 b9 [2] d9 bf [2] c5 b8 [2] d9 97 }

  condition:
    any of them
}