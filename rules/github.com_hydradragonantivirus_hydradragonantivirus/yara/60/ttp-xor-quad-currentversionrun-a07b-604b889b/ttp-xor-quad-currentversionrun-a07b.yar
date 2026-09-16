rule TTP_XOR_QUAD_CurrentVersionRun_a07b {
  strings:
    $key_a07b = { f3 14 [2] d7 1a [2] fc 36 [2] d2 14 [2] c6 0f [2] c9 15 [2] d7 08 [2] d5 09 [2] ce 0f [2] d2 08 [2] ce 27 }

  condition:
    any of them
}