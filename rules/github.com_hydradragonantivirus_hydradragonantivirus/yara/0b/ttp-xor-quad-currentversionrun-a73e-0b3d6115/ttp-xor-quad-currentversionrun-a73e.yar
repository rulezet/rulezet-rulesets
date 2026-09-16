rule TTP_XOR_QUAD_CurrentVersionRun_a73e {
  strings:
    $key_a73e = { f4 51 [2] d0 5f [2] fb 73 [2] d5 51 [2] c1 4a [2] ce 50 [2] d0 4d [2] d2 4c [2] c9 4a [2] d5 4d [2] c9 62 }

  condition:
    any of them
}