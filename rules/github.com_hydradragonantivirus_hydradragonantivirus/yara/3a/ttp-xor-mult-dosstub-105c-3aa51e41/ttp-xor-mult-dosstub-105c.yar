rule TTP_XOR_MULT_DOSStub_105c {
  strings:
    $key_105c = { 44 34 [2] 30 2c [2] 77 2e [2] 30 3f [2] 7e 33 [2] 72 39 [2] 65 32 [2] 7e 7c [2] 43 }

  condition:
    any of them
}