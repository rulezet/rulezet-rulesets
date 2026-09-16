rule TTP_XOR_MULT_DOSStub_f690 {
  strings:
    $key_f690 = { a2 f8 [2] d6 e0 [2] 91 e2 [2] d6 f3 [2] 98 ff [2] 94 f5 [2] 83 fe [2] 98 b0 [2] a5 }

  condition:
    any of them
}