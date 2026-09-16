rule TTP_XOR_MULT_DOSStub_3f2c {
  strings:
    $key_3f2c = { 6b 44 [2] 1f 5c [2] 58 5e [2] 1f 4f [2] 51 43 [2] 5d 49 [2] 4a 42 [2] 51 0c [2] 6c }

  condition:
    any of them
}