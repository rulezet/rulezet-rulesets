rule TTP_XOR_MULT_DOSStub_0f0c {
  strings:
    $key_0f0c = { 5b 64 [2] 2f 7c [2] 68 7e [2] 2f 6f [2] 61 63 [2] 6d 69 [2] 7a 62 [2] 61 2c [2] 5c }

  condition:
    any of them
}