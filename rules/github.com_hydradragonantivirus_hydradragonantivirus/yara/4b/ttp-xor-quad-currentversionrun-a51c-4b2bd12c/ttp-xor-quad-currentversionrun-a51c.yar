rule TTP_XOR_QUAD_CurrentVersionRun_a51c {
  strings:
    $key_a51c = { f6 73 [2] d2 7d [2] f9 51 [2] d7 73 [2] c3 68 [2] cc 72 [2] d2 6f [2] d0 6e [2] cb 68 [2] d7 6f [2] cb 40 }

  condition:
    any of them
}