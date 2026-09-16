rule TTP_XOR_QUAD_CurrentVersionRun_bbcc {
  strings:
    $key_bbcc = { e8 a3 [2] cc ad [2] e7 81 [2] c9 a3 [2] dd b8 [2] d2 a2 [2] cc bf [2] ce be [2] d5 b8 [2] c9 bf [2] d5 90 }

  condition:
    any of them
}