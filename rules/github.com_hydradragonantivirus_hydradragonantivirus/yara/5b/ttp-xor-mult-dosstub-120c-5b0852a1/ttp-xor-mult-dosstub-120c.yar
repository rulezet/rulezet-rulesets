rule TTP_XOR_MULT_DOSStub_120c {
  strings:
    $key_120c = { 46 64 [2] 32 7c [2] 75 7e [2] 32 6f [2] 7c 63 [2] 70 69 [2] 67 62 [2] 7c 2c [2] 41 }

  condition:
    any of them
}