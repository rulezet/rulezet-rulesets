rule TTP_XOR_MULT_DOSStub_5f36 {
  strings:
    $key_5f36 = { 0b 5e [2] 7f 46 [2] 38 44 [2] 7f 55 [2] 31 59 [2] 3d 53 [2] 2a 58 [2] 31 16 [2] 0c }

  condition:
    any of them
}