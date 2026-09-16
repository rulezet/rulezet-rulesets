rule TTP_XOR_MULT_DOSStub_195c {
  strings:
    $key_195c = { 4d 34 [2] 39 2c [2] 7e 2e [2] 39 3f [2] 77 33 [2] 7b 39 [2] 6c 32 [2] 77 7c [2] 4a }

  condition:
    any of them
}