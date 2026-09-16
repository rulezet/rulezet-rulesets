rule TTP_XOR_QUAD_CurrentVersionRun_bada {
  strings:
    $key_bada = { e9 b5 [2] cd bb [2] e6 97 [2] c8 b5 [2] dc ae [2] d3 b4 [2] cd a9 [2] cf a8 [2] d4 ae [2] c8 a9 [2] d4 86 }

  condition:
    any of them
}