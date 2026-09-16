rule TTP_XOR_MULT_DOSStub_f20c {
  strings:
    $key_f20c = { a6 64 [2] d2 7c [2] 95 7e [2] d2 6f [2] 9c 63 [2] 90 69 [2] 87 62 [2] 9c 2c [2] a1 }

  condition:
    any of them
}