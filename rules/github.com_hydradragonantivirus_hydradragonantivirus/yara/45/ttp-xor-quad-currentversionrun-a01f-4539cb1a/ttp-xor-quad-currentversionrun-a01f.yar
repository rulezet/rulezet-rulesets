rule TTP_XOR_QUAD_CurrentVersionRun_a01f {
  strings:
    $key_a01f = { f3 70 [2] d7 7e [2] fc 52 [2] d2 70 [2] c6 6b [2] c9 71 [2] d7 6c [2] d5 6d [2] ce 6b [2] d2 6c [2] ce 43 }

  condition:
    any of them
}