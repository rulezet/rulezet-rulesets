rule TTP_XOR_MULT_DOSStub_f028 {
  strings:
    $key_f028 = { a4 40 [2] d0 58 [2] 97 5a [2] d0 4b [2] 9e 47 [2] 92 4d [2] 85 46 [2] 9e 08 [2] a3 }

  condition:
    any of them
}