rule TTP_XOR_MULT_DOSStub_382e {
  strings:
    $key_382e = { 6c 46 [2] 18 5e [2] 5f 5c [2] 18 4d [2] 56 41 [2] 5a 4b [2] 4d 40 [2] 56 0e [2] 6b }

  condition:
    any of them
}