rule TTP_XOR_QUAD_CurrentVersionRun_b64d {
  strings:
    $key_b64d = { e5 22 [2] c1 2c [2] ea 00 [2] c4 22 [2] d0 39 [2] df 23 [2] c1 3e [2] c3 3f [2] d8 39 [2] c4 3e [2] d8 11 }

  condition:
    any of them
}