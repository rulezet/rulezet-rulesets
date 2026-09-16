rule TTP_XOR_MULT_DOSStub_3b90 {
  strings:
    $key_3b90 = { 6f f8 [2] 1b e0 [2] 5c e2 [2] 1b f3 [2] 55 ff [2] 59 f5 [2] 4e fe [2] 55 b0 [2] 68 }

  condition:
    any of them
}