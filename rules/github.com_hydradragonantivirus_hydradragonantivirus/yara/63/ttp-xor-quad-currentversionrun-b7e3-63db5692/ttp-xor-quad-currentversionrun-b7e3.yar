rule TTP_XOR_QUAD_CurrentVersionRun_b7e3 {
  strings:
    $key_b7e3 = { e4 8c [2] c0 82 [2] eb ae [2] c5 8c [2] d1 97 [2] de 8d [2] c0 90 [2] c2 91 [2] d9 97 [2] c5 90 [2] d9 bf }

  condition:
    any of them
}