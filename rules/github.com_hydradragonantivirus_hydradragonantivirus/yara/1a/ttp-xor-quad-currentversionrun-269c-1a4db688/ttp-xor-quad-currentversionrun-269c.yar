rule TTP_XOR_QUAD_CurrentVersionRun_269c {
  strings:
    $key_269c = { 75 f3 [2] 51 fd [2] 7a d1 [2] 54 f3 [2] 40 e8 [2] 4f f2 [2] 51 ef [2] 53 ee [2] 48 e8 [2] 54 ef [2] 48 c0 }

  condition:
    any of them
}