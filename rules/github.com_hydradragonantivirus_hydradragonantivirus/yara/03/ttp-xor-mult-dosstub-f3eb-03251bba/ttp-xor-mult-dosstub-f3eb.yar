rule TTP_XOR_MULT_DOSStub_f3eb {
  strings:
    $key_f3eb = { a7 83 [2] d3 9b [2] 94 99 [2] d3 88 [2] 9d 84 [2] 91 8e [2] 86 85 [2] 9d cb [2] a0 }

  condition:
    any of them
}