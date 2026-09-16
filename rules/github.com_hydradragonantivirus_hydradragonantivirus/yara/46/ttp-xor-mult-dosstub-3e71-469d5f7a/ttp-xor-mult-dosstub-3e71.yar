rule TTP_XOR_MULT_DOSStub_3e71 {
  strings:
    $key_3e71 = { 6a 19 [2] 1e 01 [2] 59 03 [2] 1e 12 [2] 50 1e [2] 5c 14 [2] 4b 1f [2] 50 51 [2] 6d }

  condition:
    any of them
}