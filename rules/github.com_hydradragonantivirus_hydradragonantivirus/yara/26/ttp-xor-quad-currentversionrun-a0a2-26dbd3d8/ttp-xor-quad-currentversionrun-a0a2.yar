rule TTP_XOR_QUAD_CurrentVersionRun_a0a2 {
  strings:
    $key_a0a2 = { f3 cd [2] d7 c3 [2] fc ef [2] d2 cd [2] c6 d6 [2] c9 cc [2] d7 d1 [2] d5 d0 [2] ce d6 [2] d2 d1 [2] ce fe }

  condition:
    any of them
}