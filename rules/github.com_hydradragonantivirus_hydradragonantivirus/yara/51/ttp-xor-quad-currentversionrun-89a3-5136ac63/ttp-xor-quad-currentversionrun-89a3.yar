rule TTP_XOR_QUAD_CurrentVersionRun_89a3 {
  strings:
    $key_89a3 = { da cc [2] fe c2 [2] d5 ee [2] fb cc [2] ef d7 [2] e0 cd [2] fe d0 [2] fc d1 [2] e7 d7 [2] fb d0 [2] e7 ff }

  condition:
    any of them
}