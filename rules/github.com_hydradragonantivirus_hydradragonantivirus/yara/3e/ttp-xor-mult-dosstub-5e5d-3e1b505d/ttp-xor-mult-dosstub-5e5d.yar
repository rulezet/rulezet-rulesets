rule TTP_XOR_MULT_DOSStub_5e5d {
  strings:
    $key_5e5d = { 0a 35 [2] 7e 2d [2] 39 2f [2] 7e 3e [2] 30 32 [2] 3c 38 [2] 2b 33 [2] 30 7d [2] 0d }

  condition:
    any of them
}