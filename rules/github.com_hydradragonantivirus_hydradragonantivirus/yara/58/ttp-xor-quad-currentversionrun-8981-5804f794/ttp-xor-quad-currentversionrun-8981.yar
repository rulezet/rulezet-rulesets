rule TTP_XOR_QUAD_CurrentVersionRun_8981 {
  strings:
    $key_8981 = { da ee [2] fe e0 [2] d5 cc [2] fb ee [2] ef f5 [2] e0 ef [2] fe f2 [2] fc f3 [2] e7 f5 [2] fb f2 [2] e7 dd }

  condition:
    any of them
}