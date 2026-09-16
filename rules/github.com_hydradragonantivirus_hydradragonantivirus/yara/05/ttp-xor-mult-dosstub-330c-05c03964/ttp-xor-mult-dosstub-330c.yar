rule TTP_XOR_MULT_DOSStub_330c {
  strings:
    $key_330c = { 67 64 [2] 13 7c [2] 54 7e [2] 13 6f [2] 5d 63 [2] 51 69 [2] 46 62 [2] 5d 2c [2] 60 }

  condition:
    any of them
}