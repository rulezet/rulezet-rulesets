rule TTP_XOR_QUAD_CurrentVersionRun_a74a {
  strings:
    $key_a74a = { f4 25 [2] d0 2b [2] fb 07 [2] d5 25 [2] c1 3e [2] ce 24 [2] d0 39 [2] d2 38 [2] c9 3e [2] d5 39 [2] c9 16 }

  condition:
    any of them
}