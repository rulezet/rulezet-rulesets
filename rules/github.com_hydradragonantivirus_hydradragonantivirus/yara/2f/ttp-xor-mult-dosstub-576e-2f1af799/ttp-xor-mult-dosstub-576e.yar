rule TTP_XOR_MULT_DOSStub_576e {
  strings:
    $key_576e = { 03 06 [2] 77 1e [2] 30 1c [2] 77 0d [2] 39 01 [2] 35 0b [2] 22 00 [2] 39 4e [2] 04 }

  condition:
    any of them
}