rule TTP_XOR_MULT_DOSStub_f229 {
  strings:
    $key_f229 = { a6 41 [2] d2 59 [2] 95 5b [2] d2 4a [2] 9c 46 [2] 90 4c [2] 87 47 [2] 9c 09 [2] a1 }

  condition:
    any of them
}