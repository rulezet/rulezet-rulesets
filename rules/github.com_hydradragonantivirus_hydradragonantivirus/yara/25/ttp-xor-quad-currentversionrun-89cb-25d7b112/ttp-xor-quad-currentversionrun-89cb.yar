rule TTP_XOR_QUAD_CurrentVersionRun_89cb {
  strings:
    $key_89cb = { da a4 [2] fe aa [2] d5 86 [2] fb a4 [2] ef bf [2] e0 a5 [2] fe b8 [2] fc b9 [2] e7 bf [2] fb b8 [2] e7 97 }

  condition:
    any of them
}