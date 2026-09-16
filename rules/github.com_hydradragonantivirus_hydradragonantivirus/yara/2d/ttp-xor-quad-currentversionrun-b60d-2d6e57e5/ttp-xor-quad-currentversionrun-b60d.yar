rule TTP_XOR_QUAD_CurrentVersionRun_b60d {
  strings:
    $key_b60d = { e5 62 [2] c1 6c [2] ea 40 [2] c4 62 [2] d0 79 [2] df 63 [2] c1 7e [2] c3 7f [2] d8 79 [2] c4 7e [2] d8 51 }

  condition:
    any of them
}