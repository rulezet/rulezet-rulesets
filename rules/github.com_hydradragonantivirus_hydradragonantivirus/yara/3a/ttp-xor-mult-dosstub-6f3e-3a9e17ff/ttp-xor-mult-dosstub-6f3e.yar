rule TTP_XOR_MULT_DOSStub_6f3e {
  strings:
    $key_6f3e = { 3b 56 [2] 4f 4e [2] 08 4c [2] 4f 5d [2] 01 51 [2] 0d 5b [2] 1a 50 [2] 01 1e [2] 3c }

  condition:
    any of them
}