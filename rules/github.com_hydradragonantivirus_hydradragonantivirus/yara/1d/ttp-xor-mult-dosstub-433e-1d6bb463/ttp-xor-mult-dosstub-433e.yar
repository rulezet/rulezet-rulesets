rule TTP_XOR_MULT_DOSStub_433e {
  strings:
    $key_433e = { 17 56 [2] 63 4e [2] 24 4c [2] 63 5d [2] 2d 51 [2] 21 5b [2] 36 50 [2] 2d 1e [2] 10 }

  condition:
    any of them
}