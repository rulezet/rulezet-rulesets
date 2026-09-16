rule TTP_XOR_QUAD_CurrentVersionRun_a72b {
  strings:
    $key_a72b = { f4 44 [2] d0 4a [2] fb 66 [2] d5 44 [2] c1 5f [2] ce 45 [2] d0 58 [2] d2 59 [2] c9 5f [2] d5 58 [2] c9 77 }

  condition:
    any of them
}