rule TTP_XOR_MULT_DOSStub_3f2e {
  strings:
    $key_3f2e = { 6b 46 [2] 1f 5e [2] 58 5c [2] 1f 4d [2] 51 41 [2] 5d 4b [2] 4a 40 [2] 51 0e [2] 6c }

  condition:
    any of them
}