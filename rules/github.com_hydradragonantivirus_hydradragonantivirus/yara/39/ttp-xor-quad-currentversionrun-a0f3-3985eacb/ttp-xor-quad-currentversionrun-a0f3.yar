rule TTP_XOR_QUAD_CurrentVersionRun_a0f3 {
  strings:
    $key_a0f3 = { f3 9c [2] d7 92 [2] fc be [2] d2 9c [2] c6 87 [2] c9 9d [2] d7 80 [2] d5 81 [2] ce 87 [2] d2 80 [2] ce af }

  condition:
    any of them
}