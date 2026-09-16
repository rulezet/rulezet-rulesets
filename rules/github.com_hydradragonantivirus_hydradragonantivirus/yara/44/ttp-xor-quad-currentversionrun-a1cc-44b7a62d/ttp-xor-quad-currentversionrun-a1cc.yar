rule TTP_XOR_QUAD_CurrentVersionRun_a1cc {
  strings:
    $key_a1cc = { f2 a3 [2] d6 ad [2] fd 81 [2] d3 a3 [2] c7 b8 [2] c8 a2 [2] d6 bf [2] d4 be [2] cf b8 [2] d3 bf [2] cf 90 }

  condition:
    any of them
}