rule TTP_XOR_MULT_DOSStub_1b91 {
  strings:
    $key_1b91 = { 4f f9 [2] 3b e1 [2] 7c e3 [2] 3b f2 [2] 75 fe [2] 79 f4 [2] 6e ff [2] 75 b1 [2] 48 }

  condition:
    any of them
}