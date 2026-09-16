rule TTP_XOR_QUAD_CurrentVersionRun_b622 {
  strings:
    $key_b622 = { e5 4d [2] c1 43 [2] ea 6f [2] c4 4d [2] d0 56 [2] df 4c [2] c1 51 [2] c3 50 [2] d8 56 [2] c4 51 [2] d8 7e }

  condition:
    any of them
}