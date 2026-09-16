rule TTP_XOR_MULT_DOSStub_3f0c {
  strings:
    $key_3f0c = { 6b 64 [2] 1f 7c [2] 58 7e [2] 1f 6f [2] 51 63 [2] 5d 69 [2] 4a 62 [2] 51 2c [2] 6c }

  condition:
    any of them
}