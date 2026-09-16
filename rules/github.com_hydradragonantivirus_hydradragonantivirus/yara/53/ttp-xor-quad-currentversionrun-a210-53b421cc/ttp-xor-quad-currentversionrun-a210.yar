rule TTP_XOR_QUAD_CurrentVersionRun_a210 {
  strings:
    $key_a210 = { f1 7f [2] d5 71 [2] fe 5d [2] d0 7f [2] c4 64 [2] cb 7e [2] d5 63 [2] d7 62 [2] cc 64 [2] d0 63 [2] cc 4c }

  condition:
    any of them
}