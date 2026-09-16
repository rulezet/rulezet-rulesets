rule TTP_XOR_MULT_DOSStub_f625 {
  strings:
    $key_f625 = { a2 4d [2] d6 55 [2] 91 57 [2] d6 46 [2] 98 4a [2] 94 40 [2] 83 4b [2] 98 05 [2] a5 }

  condition:
    any of them
}