rule TTP_XOR_QUAD_CurrentVersionRun_b9a2 {
  strings:
    $key_b9a2 = { ea cd [2] ce c3 [2] e5 ef [2] cb cd [2] df d6 [2] d0 cc [2] ce d1 [2] cc d0 [2] d7 d6 [2] cb d1 [2] d7 fe }

  condition:
    any of them
}