rule TTP_XOR_MULT_DOSStub_2f5e {
  strings:
    $key_2f5e = { 7b 36 [2] 0f 2e [2] 48 2c [2] 0f 3d [2] 41 31 [2] 4d 3b [2] 5a 30 [2] 41 7e [2] 7c }

  condition:
    any of them
}