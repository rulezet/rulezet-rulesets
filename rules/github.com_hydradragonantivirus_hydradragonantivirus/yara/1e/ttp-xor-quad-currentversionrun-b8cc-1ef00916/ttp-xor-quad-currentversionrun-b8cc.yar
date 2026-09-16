rule TTP_XOR_QUAD_CurrentVersionRun_b8cc {
  strings:
    $key_b8cc = { eb a3 [2] cf ad [2] e4 81 [2] ca a3 [2] de b8 [2] d1 a2 [2] cf bf [2] cd be [2] d6 b8 [2] ca bf [2] d6 90 }

  condition:
    any of them
}