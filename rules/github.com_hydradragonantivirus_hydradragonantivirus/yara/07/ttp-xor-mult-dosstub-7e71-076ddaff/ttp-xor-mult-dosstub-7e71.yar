rule TTP_XOR_MULT_DOSStub_7e71 {
  strings:
    $key_7e71 = { 2a 19 [2] 5e 01 [2] 19 03 [2] 5e 12 [2] 10 1e [2] 1c 14 [2] 0b 1f [2] 10 51 [2] 2d }

  condition:
    any of them
}