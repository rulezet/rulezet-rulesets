rule TTP_XOR_QUAD_CurrentVersionRun_b70c {
  strings:
    $key_b70c = { e4 63 [2] c0 6d [2] eb 41 [2] c5 63 [2] d1 78 [2] de 62 [2] c0 7f [2] c2 7e [2] d9 78 [2] c5 7f [2] d9 50 }

  condition:
    any of them
}