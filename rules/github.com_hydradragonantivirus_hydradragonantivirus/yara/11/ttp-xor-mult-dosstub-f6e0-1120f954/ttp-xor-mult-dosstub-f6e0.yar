rule TTP_XOR_MULT_DOSStub_f6e0 {
  strings:
    $key_f6e0 = { a2 88 [2] d6 90 [2] 91 92 [2] d6 83 [2] 98 8f [2] 94 85 [2] 83 8e [2] 98 c0 [2] a5 }

  condition:
    any of them
}