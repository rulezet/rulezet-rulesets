rule TTP_XOR_QUAD_CurrentVersionRun_b687 {
  strings:
    $key_b687 = { e5 e8 [2] c1 e6 [2] ea ca [2] c4 e8 [2] d0 f3 [2] df e9 [2] c1 f4 [2] c3 f5 [2] d8 f3 [2] c4 f4 [2] d8 db }

  condition:
    any of them
}