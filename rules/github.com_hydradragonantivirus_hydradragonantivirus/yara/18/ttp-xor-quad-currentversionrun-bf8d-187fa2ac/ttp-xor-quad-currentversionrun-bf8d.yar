rule TTP_XOR_QUAD_CurrentVersionRun_bf8d {
  strings:
    $key_bf8d = { ec e2 [2] c8 ec [2] e3 c0 [2] cd e2 [2] d9 f9 [2] d6 e3 [2] c8 fe [2] ca ff [2] d1 f9 [2] cd fe [2] d1 d1 }

  condition:
    any of them
}