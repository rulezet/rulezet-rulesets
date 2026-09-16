rule TTP_XOR_QUAD_CurrentVersionRun_b1fe {
  strings:
    $key_b1fe = { e2 91 [2] c6 9f [2] ed b3 [2] c3 91 [2] d7 8a [2] d8 90 [2] c6 8d [2] c4 8c [2] df 8a [2] c3 8d [2] df a2 }

  condition:
    any of them
}