rule TTP_XOR_QUAD_CurrentVersionRun_aa9a {
  strings:
    $key_aa9a = { f9 f5 [2] dd fb [2] f6 d7 [2] d8 f5 [2] cc ee [2] c3 f4 [2] dd e9 [2] df e8 [2] c4 ee [2] d8 e9 [2] c4 c6 }

  condition:
    any of them
}