rule TTP_XOR_QUAD_CurrentVersionRun_a20c {
  strings:
    $key_a20c = { f1 63 [2] d5 6d [2] fe 41 [2] d0 63 [2] c4 78 [2] cb 62 [2] d5 7f [2] d7 7e [2] cc 78 [2] d0 7f [2] cc 50 }

  condition:
    any of them
}