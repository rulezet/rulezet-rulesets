rule TTP_XOR_QUAD_CurrentVersionRun_a520 {
  strings:
    $key_a520 = { f6 4f [2] d2 41 [2] f9 6d [2] d7 4f [2] c3 54 [2] cc 4e [2] d2 53 [2] d0 52 [2] cb 54 [2] d7 53 [2] cb 7c }

  condition:
    any of them
}