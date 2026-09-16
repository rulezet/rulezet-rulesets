rule TTP_XOR_MULT_DOSStub_f056 {
  strings:
    $key_f056 = { a4 3e [2] d0 26 [2] 97 24 [2] d0 35 [2] 9e 39 [2] 92 33 [2] 85 38 [2] 9e 76 [2] a3 }

  condition:
    any of them
}