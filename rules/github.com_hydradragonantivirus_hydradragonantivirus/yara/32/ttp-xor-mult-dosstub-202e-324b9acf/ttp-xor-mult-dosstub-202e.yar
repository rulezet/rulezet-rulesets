rule TTP_XOR_MULT_DOSStub_202e {
  strings:
    $key_202e = { 74 46 [2] 00 5e [2] 47 5c [2] 00 4d [2] 4e 41 [2] 42 4b [2] 55 40 [2] 4e 0e [2] 73 }

  condition:
    any of them
}