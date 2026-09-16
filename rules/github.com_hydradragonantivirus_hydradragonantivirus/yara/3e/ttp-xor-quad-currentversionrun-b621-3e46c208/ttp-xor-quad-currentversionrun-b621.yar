rule TTP_XOR_QUAD_CurrentVersionRun_b621 {
  strings:
    $key_b621 = { e5 4e [2] c1 40 [2] ea 6c [2] c4 4e [2] d0 55 [2] df 4f [2] c1 52 [2] c3 53 [2] d8 55 [2] c4 52 [2] d8 7d }

  condition:
    any of them
}