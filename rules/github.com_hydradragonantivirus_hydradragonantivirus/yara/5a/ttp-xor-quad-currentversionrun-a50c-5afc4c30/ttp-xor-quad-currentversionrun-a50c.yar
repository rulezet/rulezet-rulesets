rule TTP_XOR_QUAD_CurrentVersionRun_a50c {
  strings:
    $key_a50c = { f6 63 [2] d2 6d [2] f9 41 [2] d7 63 [2] c3 78 [2] cc 62 [2] d2 7f [2] d0 7e [2] cb 78 [2] d7 7f [2] cb 50 }

  condition:
    any of them
}