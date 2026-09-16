rule TTP_XOR_MULT_DOSStub_f36e {
  strings:
    $key_f36e = { a7 06 [2] d3 1e [2] 94 1c [2] d3 0d [2] 9d 01 [2] 91 0b [2] 86 00 [2] 9d 4e [2] a0 }

  condition:
    any of them
}