rule TTP_XOR_MULT_DOSStub_248f {
  strings:
    $key_248f = { 70 e7 [2] 04 ff [2] 43 fd [2] 04 ec [2] 4a e0 [2] 46 ea [2] 51 e1 [2] 4a af [2] 77 }

  condition:
    any of them
}