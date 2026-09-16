rule TTP_XOR_QUAD_CurrentVersionRun_a08a {
  strings:
    $key_a08a = { f3 e5 [2] d7 eb [2] fc c7 [2] d2 e5 [2] c6 fe [2] c9 e4 [2] d7 f9 [2] d5 f8 [2] ce fe [2] d2 f9 [2] ce d6 }

  condition:
    any of them
}