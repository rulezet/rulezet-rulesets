rule TTP_XOR_QUAD_CurrentVersionRun_8fcc {
  strings:
    $key_8fcc = { dc a3 [2] f8 ad [2] d3 81 [2] fd a3 [2] e9 b8 [2] e6 a2 [2] f8 bf [2] fa be [2] e1 b8 [2] fd bf [2] e1 90 }

  condition:
    any of them
}