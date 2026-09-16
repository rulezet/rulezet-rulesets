rule TTP_XOR_MULT_DOSStub_bb90 {
  strings:
    $key_bb90 = { ef f8 [2] 9b e0 [2] dc e2 [2] 9b f3 [2] d5 ff [2] d9 f5 [2] ce fe [2] d5 b0 [2] e8 }

  condition:
    any of them
}