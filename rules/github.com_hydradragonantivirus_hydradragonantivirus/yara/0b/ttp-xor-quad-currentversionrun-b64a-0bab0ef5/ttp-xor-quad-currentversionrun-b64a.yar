rule TTP_XOR_QUAD_CurrentVersionRun_b64a {
  strings:
    $key_b64a = { e5 25 [2] c1 2b [2] ea 07 [2] c4 25 [2] d0 3e [2] df 24 [2] c1 39 [2] c3 38 [2] d8 3e [2] c4 39 [2] d8 16 }

  condition:
    any of them
}