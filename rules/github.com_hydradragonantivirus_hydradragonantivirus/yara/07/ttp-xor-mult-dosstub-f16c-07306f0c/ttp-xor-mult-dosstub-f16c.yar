rule TTP_XOR_MULT_DOSStub_f16c {
  strings:
    $key_f16c = { a5 04 [2] d1 1c [2] 96 1e [2] d1 0f [2] 9f 03 [2] 93 09 [2] 84 02 [2] 9f 4c [2] a2 }

  condition:
    any of them
}