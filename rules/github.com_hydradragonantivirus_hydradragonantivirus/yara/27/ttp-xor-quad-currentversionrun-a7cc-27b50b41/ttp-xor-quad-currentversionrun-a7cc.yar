rule TTP_XOR_QUAD_CurrentVersionRun_a7cc {
  strings:
    $key_a7cc = { f4 a3 [2] d0 ad [2] fb 81 [2] d5 a3 [2] c1 b8 [2] ce a2 [2] d0 bf [2] d2 be [2] c9 b8 [2] d5 bf [2] c9 90 }

  condition:
    any of them
}