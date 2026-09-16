rule TTP_XOR_QUAD_CurrentVersionRun_a0fe {
  strings:
    $key_a0fe = { f3 91 [2] d7 9f [2] fc b3 [2] d2 91 [2] c6 8a [2] c9 90 [2] d7 8d [2] d5 8c [2] ce 8a [2] d2 8d [2] ce a2 }

  condition:
    any of them
}