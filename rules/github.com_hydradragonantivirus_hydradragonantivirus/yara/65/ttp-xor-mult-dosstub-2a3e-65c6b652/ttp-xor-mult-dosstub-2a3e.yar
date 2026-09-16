rule TTP_XOR_MULT_DOSStub_2a3e {
  strings:
    $key_2a3e = { 7e 56 [2] 0a 4e [2] 4d 4c [2] 0a 5d [2] 44 51 [2] 48 5b [2] 5f 50 [2] 44 1e [2] 79 }

  condition:
    any of them
}