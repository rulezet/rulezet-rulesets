rule TTP_XOR_QUAD_CurrentVersionRun_a50f {
  strings:
    $key_a50f = { f6 60 [2] d2 6e [2] f9 42 [2] d7 60 [2] c3 7b [2] cc 61 [2] d2 7c [2] d0 7d [2] cb 7b [2] d7 7c [2] cb 53 }

  condition:
    any of them
}