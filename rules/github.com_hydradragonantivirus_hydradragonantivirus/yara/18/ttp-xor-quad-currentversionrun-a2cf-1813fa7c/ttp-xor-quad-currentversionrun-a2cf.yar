rule TTP_XOR_QUAD_CurrentVersionRun_a2cf {
  strings:
    $key_a2cf = { f1 a0 [2] d5 ae [2] fe 82 [2] d0 a0 [2] c4 bb [2] cb a1 [2] d5 bc [2] d7 bd [2] cc bb [2] d0 bc [2] cc 93 }

  condition:
    any of them
}