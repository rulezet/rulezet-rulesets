rule TTP_XOR_MULT_DOSStub_5e01 {
  strings:
    $key_5e01 = { 0a 69 [2] 7e 71 [2] 39 73 [2] 7e 62 [2] 30 6e [2] 3c 64 [2] 2b 6f [2] 30 21 [2] 0d }

  condition:
    any of them
}