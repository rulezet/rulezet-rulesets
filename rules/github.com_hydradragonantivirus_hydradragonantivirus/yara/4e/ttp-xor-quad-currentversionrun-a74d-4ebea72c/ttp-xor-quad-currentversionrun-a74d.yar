rule TTP_XOR_QUAD_CurrentVersionRun_a74d {
  strings:
    $key_a74d = { f4 22 [2] d0 2c [2] fb 00 [2] d5 22 [2] c1 39 [2] ce 23 [2] d0 3e [2] d2 3f [2] c9 39 [2] d5 3e [2] c9 11 }

  condition:
    any of them
}