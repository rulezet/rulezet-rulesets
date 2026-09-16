rule TTP_XOR_QUAD_CurrentVersionRun_b64f {
  strings:
    $key_b64f = { e5 20 [2] c1 2e [2] ea 02 [2] c4 20 [2] d0 3b [2] df 21 [2] c1 3c [2] c3 3d [2] d8 3b [2] c4 3c [2] d8 13 }

  condition:
    any of them
}