rule TTP_XOR_QUAD_CurrentVersionRun_bf8c {
  strings:
    $key_bf8c = { ec e3 [2] c8 ed [2] e3 c1 [2] cd e3 [2] d9 f8 [2] d6 e2 [2] c8 ff [2] ca fe [2] d1 f8 [2] cd ff [2] d1 d0 }

  condition:
    any of them
}