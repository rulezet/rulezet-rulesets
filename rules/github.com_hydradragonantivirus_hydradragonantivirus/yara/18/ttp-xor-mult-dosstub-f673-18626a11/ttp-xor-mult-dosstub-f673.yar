rule TTP_XOR_MULT_DOSStub_f673 {
  strings:
    $key_f673 = { a2 1b [2] d6 03 [2] 91 01 [2] d6 10 [2] 98 1c [2] 94 16 [2] 83 1d [2] 98 53 [2] a5 }

  condition:
    any of them
}