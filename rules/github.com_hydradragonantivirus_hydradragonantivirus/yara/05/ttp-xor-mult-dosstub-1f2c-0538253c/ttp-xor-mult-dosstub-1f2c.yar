rule TTP_XOR_MULT_DOSStub_1f2c {
  strings:
    $key_1f2c = { 4b 44 [2] 3f 5c [2] 78 5e [2] 3f 4f [2] 71 43 [2] 7d 49 [2] 6a 42 [2] 71 0c [2] 4c }

  condition:
    any of them
}