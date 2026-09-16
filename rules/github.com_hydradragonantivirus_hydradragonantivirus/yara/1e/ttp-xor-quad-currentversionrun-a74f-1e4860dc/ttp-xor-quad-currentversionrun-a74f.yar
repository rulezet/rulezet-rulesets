rule TTP_XOR_QUAD_CurrentVersionRun_a74f {
  strings:
    $key_a74f = { f4 20 [2] d0 2e [2] fb 02 [2] d5 20 [2] c1 3b [2] ce 21 [2] d0 3c [2] d2 3d [2] c9 3b [2] d5 3c [2] c9 13 }

  condition:
    any of them
}