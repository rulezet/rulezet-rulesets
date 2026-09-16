rule TTP_XOR_MULT_DOSStub_2a1e {
  strings:
    $key_2a1e = { 7e 76 [2] 0a 6e [2] 4d 6c [2] 0a 7d [2] 44 71 [2] 48 7b [2] 5f 70 [2] 44 3e [2] 79 }

  condition:
    any of them
}