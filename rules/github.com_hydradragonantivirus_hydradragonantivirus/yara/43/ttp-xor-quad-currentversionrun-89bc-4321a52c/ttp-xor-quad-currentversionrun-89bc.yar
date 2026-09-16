rule TTP_XOR_QUAD_CurrentVersionRun_89bc {
  strings:
    $key_89bc = { da d3 [2] fe dd [2] d5 f1 [2] fb d3 [2] ef c8 [2] e0 d2 [2] fe cf [2] fc ce [2] e7 c8 [2] fb cf [2] e7 e0 }

  condition:
    any of them
}