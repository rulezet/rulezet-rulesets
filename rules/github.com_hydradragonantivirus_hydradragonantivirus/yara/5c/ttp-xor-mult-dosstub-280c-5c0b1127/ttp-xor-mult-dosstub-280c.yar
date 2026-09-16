rule TTP_XOR_MULT_DOSStub_280c {
  strings:
    $key_280c = { 7c 64 [2] 08 7c [2] 4f 7e [2] 08 6f [2] 46 63 [2] 4a 69 [2] 5d 62 [2] 46 2c [2] 7b }

  condition:
    any of them
}