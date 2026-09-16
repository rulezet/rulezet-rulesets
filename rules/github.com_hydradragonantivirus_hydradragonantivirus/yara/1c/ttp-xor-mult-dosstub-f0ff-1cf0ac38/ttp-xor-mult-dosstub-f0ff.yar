rule TTP_XOR_MULT_DOSStub_f0ff {
  strings:
    $key_f0ff = { a4 97 [2] d0 8f [2] 97 8d [2] d0 9c [2] 9e 90 [2] 92 9a [2] 85 91 [2] 9e df [2] a3 }

  condition:
    any of them
}