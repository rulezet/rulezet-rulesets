rule TTP_XOR_MULT_DOSStub_1f0c {
  strings:
    $key_1f0c = { 4b 64 [2] 3f 7c [2] 78 7e [2] 3f 6f [2] 71 63 [2] 7d 69 [2] 6a 62 [2] 71 2c [2] 4c }

  condition:
    any of them
}