rule TTP_XOR_MULT_DOSStub_f644 {
  strings:
    $key_f644 = { a2 2c [2] d6 34 [2] 91 36 [2] d6 27 [2] 98 2b [2] 94 21 [2] 83 2a [2] 98 64 [2] a5 }

  condition:
    any of them
}