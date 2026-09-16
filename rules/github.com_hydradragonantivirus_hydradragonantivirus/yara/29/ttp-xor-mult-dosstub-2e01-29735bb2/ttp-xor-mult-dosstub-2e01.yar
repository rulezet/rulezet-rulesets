rule TTP_XOR_MULT_DOSStub_2e01 {
  strings:
    $key_2e01 = { 7a 69 [2] 0e 71 [2] 49 73 [2] 0e 62 [2] 40 6e [2] 4c 64 [2] 5b 6f [2] 40 21 [2] 7d }

  condition:
    any of them
}