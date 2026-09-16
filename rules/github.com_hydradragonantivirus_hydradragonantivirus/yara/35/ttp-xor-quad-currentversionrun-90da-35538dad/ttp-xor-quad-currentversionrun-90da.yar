rule TTP_XOR_QUAD_CurrentVersionRun_90da {
  strings:
    $key_90da = { c3 b5 [2] e7 bb [2] cc 97 [2] e2 b5 [2] f6 ae [2] f9 b4 [2] e7 a9 [2] e5 a8 [2] fe ae [2] e2 a9 [2] fe 86 }

  condition:
    any of them
}