rule TTP_XOR_QUAD_CurrentVersionRun_b9b8 {
  strings:
    $key_b9b8 = { ea d7 [2] ce d9 [2] e5 f5 [2] cb d7 [2] df cc [2] d0 d6 [2] ce cb [2] cc ca [2] d7 cc [2] cb cb [2] d7 e4 }

  condition:
    any of them
}