rule TTP_XOR_QUAD_CurrentVersionRun_b5dd {
  strings:
    $key_b5dd = { e6 b2 [2] c2 bc [2] e9 90 [2] c7 b2 [2] d3 a9 [2] dc b3 [2] c2 ae [2] c0 af [2] db a9 [2] c7 ae [2] db 81 }

  condition:
    any of them
}