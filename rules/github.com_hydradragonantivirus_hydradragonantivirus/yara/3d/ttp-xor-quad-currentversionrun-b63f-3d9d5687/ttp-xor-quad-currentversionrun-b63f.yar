rule TTP_XOR_QUAD_CurrentVersionRun_b63f {
  strings:
    $key_b63f = { e5 50 [2] c1 5e [2] ea 72 [2] c4 50 [2] d0 4b [2] df 51 [2] c1 4c [2] c3 4d [2] d8 4b [2] c4 4c [2] d8 63 }

  condition:
    any of them
}