rule TTP_XOR_MULT_DOSStub_504c {
  strings:
    $key_504c = { 04 24 [2] 70 3c [2] 37 3e [2] 70 2f [2] 3e 23 [2] 32 29 [2] 25 22 [2] 3e 6c [2] 03 }

  condition:
    any of them
}