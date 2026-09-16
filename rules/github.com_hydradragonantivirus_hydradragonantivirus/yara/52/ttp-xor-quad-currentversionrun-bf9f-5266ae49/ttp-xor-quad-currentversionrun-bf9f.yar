rule TTP_XOR_QUAD_CurrentVersionRun_bf9f {
  strings:
    $key_bf9f = { ec f0 [2] c8 fe [2] e3 d2 [2] cd f0 [2] d9 eb [2] d6 f1 [2] c8 ec [2] ca ed [2] d1 eb [2] cd ec [2] d1 c3 }

  condition:
    any of them
}