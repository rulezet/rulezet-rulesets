rule TTP_XOR_MULT_DOSStub_3f4c {
  strings:
    $key_3f4c = { 6b 24 [2] 1f 3c [2] 58 3e [2] 1f 2f [2] 51 23 [2] 5d 29 [2] 4a 22 [2] 51 6c [2] 6c }

  condition:
    any of them
}