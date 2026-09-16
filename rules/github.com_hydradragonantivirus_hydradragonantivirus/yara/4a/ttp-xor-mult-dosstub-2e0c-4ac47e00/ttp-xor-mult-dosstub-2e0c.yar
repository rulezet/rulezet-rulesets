rule TTP_XOR_MULT_DOSStub_2e0c {
  strings:
    $key_2e0c = { 7a 64 [2] 0e 7c [2] 49 7e [2] 0e 6f [2] 40 63 [2] 4c 69 [2] 5b 62 [2] 40 2c [2] 7d }

  condition:
    any of them
}