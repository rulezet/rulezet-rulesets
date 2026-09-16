rule TTP_XOR_QUAD_CurrentVersionRun_a71e {
  strings:
    $key_a71e = { f4 71 [2] d0 7f [2] fb 53 [2] d5 71 [2] c1 6a [2] ce 70 [2] d0 6d [2] d2 6c [2] c9 6a [2] d5 6d [2] c9 42 }

  condition:
    any of them
}