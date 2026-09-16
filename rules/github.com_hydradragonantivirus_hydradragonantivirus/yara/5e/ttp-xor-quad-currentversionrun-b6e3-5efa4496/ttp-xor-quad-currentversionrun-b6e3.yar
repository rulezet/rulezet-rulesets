rule TTP_XOR_QUAD_CurrentVersionRun_b6e3 {
  strings:
    $key_b6e3 = { e5 8c [2] c1 82 [2] ea ae [2] c4 8c [2] d0 97 [2] df 8d [2] c1 90 [2] c3 91 [2] d8 97 [2] c4 90 [2] d8 bf }

  condition:
    any of them
}