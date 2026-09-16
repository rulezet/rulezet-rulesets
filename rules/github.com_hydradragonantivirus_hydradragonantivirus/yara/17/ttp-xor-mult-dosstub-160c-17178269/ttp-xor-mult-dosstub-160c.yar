rule TTP_XOR_MULT_DOSStub_160c {
  strings:
    $key_160c = { 42 64 [2] 36 7c [2] 71 7e [2] 36 6f [2] 78 63 [2] 74 69 [2] 63 62 [2] 78 2c [2] 45 }

  condition:
    any of them
}