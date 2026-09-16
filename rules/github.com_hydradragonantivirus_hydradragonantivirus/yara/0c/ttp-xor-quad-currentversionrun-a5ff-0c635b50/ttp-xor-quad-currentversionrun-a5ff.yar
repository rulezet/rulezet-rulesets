rule TTP_XOR_QUAD_CurrentVersionRun_a5ff {
  strings:
    $key_a5ff = { f6 90 [2] d2 9e [2] f9 b2 [2] d7 90 [2] c3 8b [2] cc 91 [2] d2 8c [2] d0 8d [2] cb 8b [2] d7 8c [2] cb a3 }

  condition:
    any of them
}