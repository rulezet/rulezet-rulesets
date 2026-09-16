rule TTP_XOR_MULT_DOSStub_0f2e {
  strings:
    $key_0f2e = { 5b 46 [2] 2f 5e [2] 68 5c [2] 2f 4d [2] 61 41 [2] 6d 4b [2] 7a 40 [2] 61 0e [2] 5c }

  condition:
    any of them
}