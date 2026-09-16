rule TTP_XOR_QUAD_CurrentVersionRun_b606 {
  strings:
    $key_b606 = { e5 69 [2] c1 67 [2] ea 4b [2] c4 69 [2] d0 72 [2] df 68 [2] c1 75 [2] c3 74 [2] d8 72 [2] c4 75 [2] d8 5a }

  condition:
    any of them
}