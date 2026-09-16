rule TTP_XOR_MULT_DOSStub_f60c {
  strings:
    $key_f60c = { a2 64 [2] d6 7c [2] 91 7e [2] d6 6f [2] 98 63 [2] 94 69 [2] 83 62 [2] 98 2c [2] a5 }

  condition:
    any of them
}