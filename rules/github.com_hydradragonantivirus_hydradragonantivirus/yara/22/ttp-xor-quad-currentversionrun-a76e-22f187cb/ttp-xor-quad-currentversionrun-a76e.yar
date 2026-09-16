rule TTP_XOR_QUAD_CurrentVersionRun_a76e {
  strings:
    $key_a76e = { f4 01 [2] d0 0f [2] fb 23 [2] d5 01 [2] c1 1a [2] ce 00 [2] d0 1d [2] d2 1c [2] c9 1a [2] d5 1d [2] c9 32 }

  condition:
    any of them
}