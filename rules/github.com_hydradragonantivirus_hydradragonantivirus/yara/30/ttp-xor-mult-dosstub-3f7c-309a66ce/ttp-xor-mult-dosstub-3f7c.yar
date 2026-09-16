rule TTP_XOR_MULT_DOSStub_3f7c {
  strings:
    $key_3f7c = { 6b 14 [2] 1f 0c [2] 58 0e [2] 1f 1f [2] 51 13 [2] 5d 19 [2] 4a 12 [2] 51 5c [2] 6c }

  condition:
    any of them
}