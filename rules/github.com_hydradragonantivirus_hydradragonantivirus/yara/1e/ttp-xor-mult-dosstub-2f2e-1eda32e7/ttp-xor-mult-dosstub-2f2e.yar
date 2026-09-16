rule TTP_XOR_MULT_DOSStub_2f2e {
  strings:
    $key_2f2e = { 7b 46 [2] 0f 5e [2] 48 5c [2] 0f 4d [2] 41 41 [2] 4d 4b [2] 5a 40 [2] 41 0e [2] 7c }

  condition:
    any of them
}