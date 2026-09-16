rule TTP_XOR_MULT_DOSStub_655c {
  strings:
    $key_655c = { 31 34 [2] 45 2c [2] 02 2e [2] 45 3f [2] 0b 33 [2] 07 39 [2] 10 32 [2] 0b 7c [2] 36 }

  condition:
    any of them
}