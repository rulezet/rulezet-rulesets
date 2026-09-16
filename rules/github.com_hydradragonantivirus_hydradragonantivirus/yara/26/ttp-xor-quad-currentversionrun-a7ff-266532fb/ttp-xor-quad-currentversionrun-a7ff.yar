rule TTP_XOR_QUAD_CurrentVersionRun_a7ff {
  strings:
    $key_a7ff = { f4 90 [2] d0 9e [2] fb b2 [2] d5 90 [2] c1 8b [2] ce 91 [2] d0 8c [2] d2 8d [2] c9 8b [2] d5 8c [2] c9 a3 }

  condition:
    any of them
}