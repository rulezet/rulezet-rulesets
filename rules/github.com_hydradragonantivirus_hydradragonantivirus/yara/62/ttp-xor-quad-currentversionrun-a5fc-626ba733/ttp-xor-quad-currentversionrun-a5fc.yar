rule TTP_XOR_QUAD_CurrentVersionRun_a5fc {
  strings:
    $key_a5fc = { f6 93 [2] d2 9d [2] f9 b1 [2] d7 93 [2] c3 88 [2] cc 92 [2] d2 8f [2] d0 8e [2] cb 88 [2] d7 8f [2] cb a0 }

  condition:
    any of them
}