rule TTP_XOR_QUAD_CurrentVersionRun_a77d {
  strings:
    $key_a77d = { f4 12 [2] d0 1c [2] fb 30 [2] d5 12 [2] c1 09 [2] ce 13 [2] d0 0e [2] d2 0f [2] c9 09 [2] d5 0e [2] c9 21 }

  condition:
    any of them
}