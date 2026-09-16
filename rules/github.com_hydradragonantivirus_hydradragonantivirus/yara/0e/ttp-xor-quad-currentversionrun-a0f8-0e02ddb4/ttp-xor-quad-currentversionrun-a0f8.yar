rule TTP_XOR_QUAD_CurrentVersionRun_a0f8 {
  strings:
    $key_a0f8 = { f3 97 [2] d7 99 [2] fc b5 [2] d2 97 [2] c6 8c [2] c9 96 [2] d7 8b [2] d5 8a [2] ce 8c [2] d2 8b [2] ce a4 }

  condition:
    any of them
}