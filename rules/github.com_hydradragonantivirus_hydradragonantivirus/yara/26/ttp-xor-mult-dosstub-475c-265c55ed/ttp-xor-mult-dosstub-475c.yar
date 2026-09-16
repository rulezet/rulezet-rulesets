rule TTP_XOR_MULT_DOSStub_475c {
  strings:
    $key_475c = { 13 34 [2] 67 2c [2] 20 2e [2] 67 3f [2] 29 33 [2] 25 39 [2] 32 32 [2] 29 7c [2] 14 }

  condition:
    any of them
}