rule TTP_XOR_QUAD_CurrentVersionRun_a71f {
  strings:
    $key_a71f = { f4 70 [2] d0 7e [2] fb 52 [2] d5 70 [2] c1 6b [2] ce 71 [2] d0 6c [2] d2 6d [2] c9 6b [2] d5 6c [2] c9 43 }

  condition:
    any of them
}