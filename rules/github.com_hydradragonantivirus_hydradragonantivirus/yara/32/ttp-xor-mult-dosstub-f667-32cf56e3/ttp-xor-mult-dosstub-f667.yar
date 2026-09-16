rule TTP_XOR_MULT_DOSStub_f667 {
  strings:
    $key_f667 = { a2 0f [2] d6 17 [2] 91 15 [2] d6 04 [2] 98 08 [2] 94 02 [2] 83 09 [2] 98 47 [2] a5 }

  condition:
    any of them
}