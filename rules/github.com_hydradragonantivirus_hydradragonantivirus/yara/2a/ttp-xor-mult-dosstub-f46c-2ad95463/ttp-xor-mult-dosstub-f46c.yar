rule TTP_XOR_MULT_DOSStub_f46c {
  strings:
    $key_f46c = { a0 04 [2] d4 1c [2] 93 1e [2] d4 0f [2] 9a 03 [2] 96 09 [2] 81 02 [2] 9a 4c [2] a7 }

  condition:
    any of them
}