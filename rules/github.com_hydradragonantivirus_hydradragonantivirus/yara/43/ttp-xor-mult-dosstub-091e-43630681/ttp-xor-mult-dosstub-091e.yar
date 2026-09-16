rule TTP_XOR_MULT_DOSStub_091e {
  strings:
    $key_091e = { 5d 76 [2] 29 6e [2] 6e 6c [2] 29 7d [2] 67 71 [2] 6b 7b [2] 7c 70 [2] 67 3e [2] 5a }

  condition:
    any of them
}