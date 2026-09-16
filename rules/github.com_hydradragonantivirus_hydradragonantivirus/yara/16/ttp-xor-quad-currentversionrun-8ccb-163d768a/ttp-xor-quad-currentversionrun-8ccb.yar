rule TTP_XOR_QUAD_CurrentVersionRun_8ccb {
  strings:
    $key_8ccb = { df a4 [2] fb aa [2] d0 86 [2] fe a4 [2] ea bf [2] e5 a5 [2] fb b8 [2] f9 b9 [2] e2 bf [2] fe b8 [2] e2 97 }

  condition:
    any of them
}