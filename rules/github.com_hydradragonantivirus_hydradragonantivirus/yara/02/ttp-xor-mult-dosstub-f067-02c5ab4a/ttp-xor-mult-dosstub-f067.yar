rule TTP_XOR_MULT_DOSStub_f067 {
  strings:
    $key_f067 = { a4 0f [2] d0 17 [2] 97 15 [2] d0 04 [2] 9e 08 [2] 92 02 [2] 85 09 [2] 9e 47 [2] a3 }

  condition:
    any of them
}