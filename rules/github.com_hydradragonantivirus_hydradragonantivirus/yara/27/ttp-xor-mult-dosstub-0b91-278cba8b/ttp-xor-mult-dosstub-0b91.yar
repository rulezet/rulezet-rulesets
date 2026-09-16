rule TTP_XOR_MULT_DOSStub_0b91 {
  strings:
    $key_0b91 = { 5f f9 [2] 2b e1 [2] 6c e3 [2] 2b f2 [2] 65 fe [2] 69 f4 [2] 7e ff [2] 65 b1 [2] 58 }

  condition:
    any of them
}