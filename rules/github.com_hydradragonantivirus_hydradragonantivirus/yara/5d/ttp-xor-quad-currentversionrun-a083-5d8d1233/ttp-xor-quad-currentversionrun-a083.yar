rule TTP_XOR_QUAD_CurrentVersionRun_a083 {
  strings:
    $key_a083 = { f3 ec [2] d7 e2 [2] fc ce [2] d2 ec [2] c6 f7 [2] c9 ed [2] d7 f0 [2] d5 f1 [2] ce f7 [2] d2 f0 [2] ce df }

  condition:
    any of them
}