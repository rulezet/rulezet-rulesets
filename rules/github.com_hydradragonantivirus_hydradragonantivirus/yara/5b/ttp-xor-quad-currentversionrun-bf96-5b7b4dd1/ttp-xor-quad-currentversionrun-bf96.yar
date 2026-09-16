rule TTP_XOR_QUAD_CurrentVersionRun_bf96 {
  strings:
    $key_bf96 = { ec f9 [2] c8 f7 [2] e3 db [2] cd f9 [2] d9 e2 [2] d6 f8 [2] c8 e5 [2] ca e4 [2] d1 e2 [2] cd e5 [2] d1 ca }

  condition:
    any of them
}