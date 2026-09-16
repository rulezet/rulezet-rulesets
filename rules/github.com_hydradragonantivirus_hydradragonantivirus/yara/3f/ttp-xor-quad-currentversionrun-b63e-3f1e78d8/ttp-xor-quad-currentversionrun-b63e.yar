rule TTP_XOR_QUAD_CurrentVersionRun_b63e {
  strings:
    $key_b63e = { e5 51 [2] c1 5f [2] ea 73 [2] c4 51 [2] d0 4a [2] df 50 [2] c1 4d [2] c3 4c [2] d8 4a [2] c4 4d [2] d8 62 }

  condition:
    any of them
}