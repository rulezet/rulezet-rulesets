rule TTP_XOR_MULT_DOSStub_073e {
  strings:
    $key_073e = { 53 56 [2] 27 4e [2] 60 4c [2] 27 5d [2] 69 51 [2] 65 5b [2] 72 50 [2] 69 1e [2] 54 }

  condition:
    any of them
}