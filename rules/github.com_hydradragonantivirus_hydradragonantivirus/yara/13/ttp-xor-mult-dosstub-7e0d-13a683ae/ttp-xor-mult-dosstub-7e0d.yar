rule TTP_XOR_MULT_DOSStub_7e0d {
  strings:
    $key_7e0d = { 2a 65 [2] 5e 7d [2] 19 7f [2] 5e 6e [2] 10 62 [2] 1c 68 [2] 0b 63 [2] 10 2d [2] 2d }

  condition:
    any of them
}