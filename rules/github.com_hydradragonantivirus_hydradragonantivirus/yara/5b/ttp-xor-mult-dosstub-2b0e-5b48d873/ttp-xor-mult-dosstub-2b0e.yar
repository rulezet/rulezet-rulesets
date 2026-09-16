rule TTP_XOR_MULT_DOSStub_2b0e {
  strings:
    $key_2b0e = { 7f 66 [2] 0b 7e [2] 4c 7c [2] 0b 6d [2] 45 61 [2] 49 6b [2] 5e 60 [2] 45 2e [2] 78 }

  condition:
    any of them
}