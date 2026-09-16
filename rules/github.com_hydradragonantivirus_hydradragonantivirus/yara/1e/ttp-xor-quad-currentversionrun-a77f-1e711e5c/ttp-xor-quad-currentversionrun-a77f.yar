rule TTP_XOR_QUAD_CurrentVersionRun_a77f {
  strings:
    $key_a77f = { f4 10 [2] d0 1e [2] fb 32 [2] d5 10 [2] c1 0b [2] ce 11 [2] d0 0c [2] d2 0d [2] c9 0b [2] d5 0c [2] c9 23 }

  condition:
    any of them
}