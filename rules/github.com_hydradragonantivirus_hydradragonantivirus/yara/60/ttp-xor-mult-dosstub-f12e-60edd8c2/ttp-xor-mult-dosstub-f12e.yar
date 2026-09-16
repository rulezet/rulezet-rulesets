rule TTP_XOR_MULT_DOSStub_f12e {
  strings:
    $key_f12e = { a5 46 [2] d1 5e [2] 96 5c [2] d1 4d [2] 9f 41 [2] 93 4b [2] 84 40 [2] 9f 0e [2] a2 }

  condition:
    any of them
}