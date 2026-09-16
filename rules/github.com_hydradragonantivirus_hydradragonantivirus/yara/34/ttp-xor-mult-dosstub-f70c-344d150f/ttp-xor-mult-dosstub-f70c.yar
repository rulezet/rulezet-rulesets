rule TTP_XOR_MULT_DOSStub_f70c {
  strings:
    $key_f70c = { a3 64 [2] d7 7c [2] 90 7e [2] d7 6f [2] 99 63 [2] 95 69 [2] 82 62 [2] 99 2c [2] a4 }

  condition:
    any of them
}