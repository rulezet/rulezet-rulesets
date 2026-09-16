rule TTP_XOR_MULT_DOSStub_2f4e {
  strings:
    $key_2f4e = { 7b 26 [2] 0f 3e [2] 48 3c [2] 0f 2d [2] 41 21 [2] 4d 2b [2] 5a 20 [2] 41 6e [2] 7c }

  condition:
    any of them
}