rule TTP_XOR_MULT_DOSStub_5e41 {
  strings:
    $key_5e41 = { 0a 29 [2] 7e 31 [2] 39 33 [2] 7e 22 [2] 30 2e [2] 3c 24 [2] 2b 2f [2] 30 61 [2] 0d }

  condition:
    any of them
}