rule TTP_XOR_QUAD_CurrentVersionRun_a221 {
  strings:
    $key_a221 = { f1 4e [2] d5 40 [2] fe 6c [2] d0 4e [2] c4 55 [2] cb 4f [2] d5 52 [2] d7 53 [2] cc 55 [2] d0 52 [2] cc 7d }

  condition:
    any of them
}