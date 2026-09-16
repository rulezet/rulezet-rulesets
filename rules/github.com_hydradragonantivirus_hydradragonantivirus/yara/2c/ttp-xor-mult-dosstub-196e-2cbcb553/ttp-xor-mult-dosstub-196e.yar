rule TTP_XOR_MULT_DOSStub_196e {
  strings:
    $key_196e = { 4d 06 [2] 39 1e [2] 7e 1c [2] 39 0d [2] 77 01 [2] 7b 0b [2] 6c 00 [2] 77 4e [2] 4a }

  condition:
    any of them
}