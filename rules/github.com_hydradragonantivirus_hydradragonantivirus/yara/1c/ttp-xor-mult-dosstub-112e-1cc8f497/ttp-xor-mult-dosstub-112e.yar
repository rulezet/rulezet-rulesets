rule TTP_XOR_MULT_DOSStub_112e {
  strings:
    $key_112e = { 45 46 [2] 31 5e [2] 76 5c [2] 31 4d [2] 7f 41 [2] 73 4b [2] 64 40 [2] 7f 0e [2] 42 }

  condition:
    any of them
}