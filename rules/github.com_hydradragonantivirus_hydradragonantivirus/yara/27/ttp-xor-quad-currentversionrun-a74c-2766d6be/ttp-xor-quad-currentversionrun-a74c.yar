rule TTP_XOR_QUAD_CurrentVersionRun_a74c {
  strings:
    $key_a74c = { f4 23 [2] d0 2d [2] fb 01 [2] d5 23 [2] c1 38 [2] ce 22 [2] d0 3f [2] d2 3e [2] c9 38 [2] d5 3f [2] c9 10 }

  condition:
    any of them
}