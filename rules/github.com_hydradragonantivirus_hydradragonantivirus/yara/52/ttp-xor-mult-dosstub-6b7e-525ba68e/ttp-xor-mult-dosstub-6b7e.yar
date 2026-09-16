rule TTP_XOR_MULT_DOSStub_6b7e {
  strings:
    $key_6b7e = { 3f 16 [2] 4b 0e [2] 0c 0c [2] 4b 1d [2] 05 11 [2] 09 1b [2] 1e 10 [2] 05 5e [2] 38 }

  condition:
    any of them
}