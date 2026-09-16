rule TTP_XOR_QUAD_CurrentVersionRun_a2e0 {
  strings:
    $key_a2e0 = { f1 8f [2] d5 81 [2] fe ad [2] d0 8f [2] c4 94 [2] cb 8e [2] d5 93 [2] d7 92 [2] cc 94 [2] d0 93 [2] cc bc }

  condition:
    any of them
}