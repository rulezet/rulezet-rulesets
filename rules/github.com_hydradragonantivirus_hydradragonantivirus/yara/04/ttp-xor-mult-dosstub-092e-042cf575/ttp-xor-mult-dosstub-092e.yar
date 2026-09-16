rule TTP_XOR_MULT_DOSStub_092e {
  strings:
    $key_092e = { 5d 46 [2] 29 5e [2] 6e 5c [2] 29 4d [2] 67 41 [2] 6b 4b [2] 7c 40 [2] 67 0e [2] 5a }

  condition:
    any of them
}