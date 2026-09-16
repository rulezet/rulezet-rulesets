rule TTP_XOR_MULT_DOSStub_7b91 {
  strings:
    $key_7b91 = { 2f f9 [2] 5b e1 [2] 1c e3 [2] 5b f2 [2] 15 fe [2] 19 f4 [2] 0e ff [2] 15 b1 [2] 28 }

  condition:
    any of them
}