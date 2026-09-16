rule TTP_XOR_MULT_DOSStub_191e {
  strings:
    $key_191e = { 4d 76 [2] 39 6e [2] 7e 6c [2] 39 7d [2] 77 71 [2] 7b 7b [2] 6c 70 [2] 77 3e [2] 4a }

  condition:
    any of them
}