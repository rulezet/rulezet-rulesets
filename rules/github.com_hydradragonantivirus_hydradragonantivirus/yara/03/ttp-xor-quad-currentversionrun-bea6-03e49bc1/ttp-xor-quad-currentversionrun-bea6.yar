rule TTP_XOR_QUAD_CurrentVersionRun_bea6 {
  strings:
    $key_bea6 = { ed c9 [2] c9 c7 [2] e2 eb [2] cc c9 [2] d8 d2 [2] d7 c8 [2] c9 d5 [2] cb d4 [2] d0 d2 [2] cc d5 [2] d0 fa }

  condition:
    any of them
}