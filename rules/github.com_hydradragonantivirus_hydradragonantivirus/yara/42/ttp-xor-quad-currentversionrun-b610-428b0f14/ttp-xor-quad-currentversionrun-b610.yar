rule TTP_XOR_QUAD_CurrentVersionRun_b610 {
  strings:
    $key_b610 = { e5 7f [2] c1 71 [2] ea 5d [2] c4 7f [2] d0 64 [2] df 7e [2] c1 63 [2] c3 62 [2] d8 64 [2] c4 63 [2] d8 4c }

  condition:
    any of them
}