rule TTP_XOR_MULT_DOSStub_f616 {
  strings:
    $key_f616 = { a2 7e [2] d6 66 [2] 91 64 [2] d6 75 [2] 98 79 [2] 94 73 [2] 83 78 [2] 98 36 [2] a5 }

  condition:
    any of them
}