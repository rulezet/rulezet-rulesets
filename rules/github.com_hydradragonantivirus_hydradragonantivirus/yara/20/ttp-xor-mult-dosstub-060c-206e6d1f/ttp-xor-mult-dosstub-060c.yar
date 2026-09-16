rule TTP_XOR_MULT_DOSStub_060c {
  strings:
    $key_060c = { 52 64 [2] 26 7c [2] 61 7e [2] 26 6f [2] 68 63 [2] 64 69 [2] 73 62 [2] 68 2c [2] 55 }

  condition:
    any of them
}