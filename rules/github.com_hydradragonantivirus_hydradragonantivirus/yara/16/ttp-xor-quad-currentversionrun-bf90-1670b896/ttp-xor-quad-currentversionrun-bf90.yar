rule TTP_XOR_QUAD_CurrentVersionRun_bf90 {
  strings:
    $key_bf90 = { ec ff [2] c8 f1 [2] e3 dd [2] cd ff [2] d9 e4 [2] d6 fe [2] c8 e3 [2] ca e2 [2] d1 e4 [2] cd e3 [2] d1 cc }

  condition:
    any of them
}