rule TTP_XOR_QUAD_CurrentVersionRun_a72f {
  strings:
    $key_a72f = { f4 40 [2] d0 4e [2] fb 62 [2] d5 40 [2] c1 5b [2] ce 41 [2] d0 5c [2] d2 5d [2] c9 5b [2] d5 5c [2] c9 73 }

  condition:
    any of them
}