rule TTP_XOR_QUAD_CurrentVersionRun_a2b7 {
  strings:
    $key_a2b7 = { f1 d8 [2] d5 d6 [2] fe fa [2] d0 d8 [2] c4 c3 [2] cb d9 [2] d5 c4 [2] d7 c5 [2] cc c3 [2] d0 c4 [2] cc eb }

  condition:
    any of them
}