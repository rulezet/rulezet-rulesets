rule TTP_XOR_MULT_DOSStub_f523 {
  strings:
    $key_f523 = { a1 4b [2] d5 53 [2] 92 51 [2] d5 40 [2] 9b 4c [2] 97 46 [2] 80 4d [2] 9b 03 [2] a6 }

  condition:
    any of them
}