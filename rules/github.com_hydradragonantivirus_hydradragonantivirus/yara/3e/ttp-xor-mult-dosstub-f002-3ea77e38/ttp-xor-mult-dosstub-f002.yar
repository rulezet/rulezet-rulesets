rule TTP_XOR_MULT_DOSStub_f002 {
  strings:
    $key_f002 = { a4 6a [2] d0 72 [2] 97 70 [2] d0 61 [2] 9e 6d [2] 92 67 [2] 85 6c [2] 9e 22 [2] a3 }

  condition:
    any of them
}