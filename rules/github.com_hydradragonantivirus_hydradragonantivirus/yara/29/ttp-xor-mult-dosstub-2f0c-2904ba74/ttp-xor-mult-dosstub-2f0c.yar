rule TTP_XOR_MULT_DOSStub_2f0c {
  strings:
    $key_2f0c = { 7b 64 [2] 0f 7c [2] 48 7e [2] 0f 6f [2] 41 63 [2] 4d 69 [2] 5a 62 [2] 41 2c [2] 7c }

  condition:
    any of them
}