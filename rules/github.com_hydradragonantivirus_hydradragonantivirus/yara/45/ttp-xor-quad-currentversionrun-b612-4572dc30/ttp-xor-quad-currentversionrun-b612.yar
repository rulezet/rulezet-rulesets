rule TTP_XOR_QUAD_CurrentVersionRun_b612 {
  strings:
    $key_b612 = { e5 7d [2] c1 73 [2] ea 5f [2] c4 7d [2] d0 66 [2] df 7c [2] c1 61 [2] c3 60 [2] d8 66 [2] c4 61 [2] d8 4e }

  condition:
    any of them
}