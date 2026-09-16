rule TTP_XOR_QUAD_CurrentVersionRun_aa9b {
  strings:
    $key_aa9b = { f9 f4 [2] dd fa [2] f6 d6 [2] d8 f4 [2] cc ef [2] c3 f5 [2] dd e8 [2] df e9 [2] c4 ef [2] d8 e8 [2] c4 c7 }

  condition:
    any of them
}