rule TTP_XOR_MULT_DOSStub_133e {
  strings:
    $key_133e = { 47 56 [2] 33 4e [2] 74 4c [2] 33 5d [2] 7d 51 [2] 71 5b [2] 66 50 [2] 7d 1e [2] 40 }

  condition:
    any of them
}