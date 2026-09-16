rule TTP_XOR_QUAD_CurrentVersionRun_b63d {
  strings:
    $key_b63d = { e5 52 [2] c1 5c [2] ea 70 [2] c4 52 [2] d0 49 [2] df 53 [2] c1 4e [2] c3 4f [2] d8 49 [2] c4 4e [2] d8 61 }

  condition:
    any of them
}