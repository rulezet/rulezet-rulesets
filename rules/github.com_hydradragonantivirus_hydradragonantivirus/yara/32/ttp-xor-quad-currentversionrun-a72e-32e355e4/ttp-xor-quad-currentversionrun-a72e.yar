rule TTP_XOR_QUAD_CurrentVersionRun_a72e {
  strings:
    $key_a72e = { f4 41 [2] d0 4f [2] fb 63 [2] d5 41 [2] c1 5a [2] ce 40 [2] d0 5d [2] d2 5c [2] c9 5a [2] d5 5d [2] c9 72 }

  condition:
    any of them
}