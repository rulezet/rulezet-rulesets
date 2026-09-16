rule TTP_XOR_MULT_DOSStub_650e {
  strings:
    $key_650e = { 31 66 [2] 45 7e [2] 02 7c [2] 45 6d [2] 0b 61 [2] 07 6b [2] 10 60 [2] 0b 2e [2] 36 }

  condition:
    any of them
}