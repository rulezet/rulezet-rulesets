rule TTP_XOR_QUAD_CurrentVersionRun_a6e3 {
  strings:
    $key_a6e3 = { f5 8c [2] d1 82 [2] fa ae [2] d4 8c [2] c0 97 [2] cf 8d [2] d1 90 [2] d3 91 [2] c8 97 [2] d4 90 [2] c8 bf }

  condition:
    any of them
}