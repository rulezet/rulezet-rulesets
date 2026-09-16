rule TTP_XOR_QUAD_CurrentVersionRun_a53f {
  strings:
    $key_a53f = { f6 50 [2] d2 5e [2] f9 72 [2] d7 50 [2] c3 4b [2] cc 51 [2] d2 4c [2] d0 4d [2] cb 4b [2] d7 4c [2] cb 63 }

  condition:
    any of them
}