rule TTP_XOR_QUAD_CurrentVersionRun_95da {
  strings:
    $key_95da = { c6 b5 [2] e2 bb [2] c9 97 [2] e7 b5 [2] f3 ae [2] fc b4 [2] e2 a9 [2] e0 a8 [2] fb ae [2] e7 a9 [2] fb 86 }

  condition:
    any of them
}