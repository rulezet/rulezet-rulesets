rule TTP_XOR_QUAD_CurrentVersionRun_a19b {
  strings:
    $key_a19b = { f2 f4 [2] d6 fa [2] fd d6 [2] d3 f4 [2] c7 ef [2] c8 f5 [2] d6 e8 [2] d4 e9 [2] cf ef [2] d3 e8 [2] cf c7 }

  condition:
    any of them
}