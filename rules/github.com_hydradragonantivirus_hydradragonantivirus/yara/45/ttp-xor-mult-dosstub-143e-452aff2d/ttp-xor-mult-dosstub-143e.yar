rule TTP_XOR_MULT_DOSStub_143e {
  strings:
    $key_143e = { 40 56 [2] 34 4e [2] 73 4c [2] 34 5d [2] 7a 51 [2] 76 5b [2] 61 50 [2] 7a 1e [2] 47 }

  condition:
    any of them
}