rule TTP_XOR_QUAD_CurrentVersionRun_a0ff {
  strings:
    $key_a0ff = { f3 90 [2] d7 9e [2] fc b2 [2] d2 90 [2] c6 8b [2] c9 91 [2] d7 8c [2] d5 8d [2] ce 8b [2] d2 8c [2] ce a3 }

  condition:
    any of them
}