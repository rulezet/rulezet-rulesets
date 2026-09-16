rule TTP_XOR_MULT_DOSStub_f50f {
  strings:
    $key_f50f = { a1 67 [2] d5 7f [2] 92 7d [2] d5 6c [2] 9b 60 [2] 97 6a [2] 80 61 [2] 9b 2f [2] a6 }

  condition:
    any of them
}