rule TTP_XOR_MULT_DOSStub_6a6e {
  strings:
    $key_6a6e = { 3e 06 [2] 4a 1e [2] 0d 1c [2] 4a 0d [2] 04 01 [2] 08 0b [2] 1f 00 [2] 04 4e [2] 39 }

  condition:
    any of them
}