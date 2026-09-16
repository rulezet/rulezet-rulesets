rule TTP_XOR_QUAD_CurrentVersionRun_b6cb {
  strings:
    $key_b6cb = { e5 a4 [2] c1 aa [2] ea 86 [2] c4 a4 [2] d0 bf [2] df a5 [2] c1 b8 [2] c3 b9 [2] d8 bf [2] c4 b8 [2] d8 97 }

  condition:
    any of them
}