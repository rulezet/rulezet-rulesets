rule TTP_XOR_QUAD_CurrentVersionRun_b296 {
  strings:
    $key_b296 = { e1 f9 [2] c5 f7 [2] ee db [2] c0 f9 [2] d4 e2 [2] db f8 [2] c5 e5 [2] c7 e4 [2] dc e2 [2] c0 e5 [2] dc ca }

  condition:
    any of them
}