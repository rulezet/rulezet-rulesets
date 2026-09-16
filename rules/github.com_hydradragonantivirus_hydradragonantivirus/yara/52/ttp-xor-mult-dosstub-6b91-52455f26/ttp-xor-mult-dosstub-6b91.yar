rule TTP_XOR_MULT_DOSStub_6b91 {
  strings:
    $key_6b91 = { 3f f9 [2] 4b e1 [2] 0c e3 [2] 4b f2 [2] 05 fe [2] 09 f4 [2] 1e ff [2] 05 b1 [2] 38 }

  condition:
    any of them
}