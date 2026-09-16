rule TTP_XOR_MULT_DOSStub_f7e3 {
  strings:
    $key_f7e3 = { a3 8b [2] d7 93 [2] 90 91 [2] d7 80 [2] 99 8c [2] 95 86 [2] 82 8d [2] 99 c3 [2] a4 }

  condition:
    any of them
}