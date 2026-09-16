rule TTP_XOR_MULT_DOSStub_615c {
  strings:
    $key_615c = { 35 34 [2] 41 2c [2] 06 2e [2] 41 3f [2] 0f 33 [2] 03 39 [2] 14 32 [2] 0f 7c [2] 32 }

  condition:
    any of them
}