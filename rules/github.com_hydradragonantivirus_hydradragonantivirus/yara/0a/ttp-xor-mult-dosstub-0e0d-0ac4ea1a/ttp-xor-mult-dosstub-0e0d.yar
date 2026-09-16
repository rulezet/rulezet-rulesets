rule TTP_XOR_MULT_DOSStub_0e0d {
  strings:
    $key_0e0d = { 5a 65 [2] 2e 7d [2] 69 7f [2] 2e 6e [2] 60 62 [2] 6c 68 [2] 7b 63 [2] 60 2d [2] 5d }

  condition:
    any of them
}