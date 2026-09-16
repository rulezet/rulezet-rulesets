rule TTP_XOR_MULT_DOSStub_2b0c {
  strings:
    $key_2b0c = { 7f 64 [2] 0b 7c [2] 4c 7e [2] 0b 6f [2] 45 63 [2] 49 69 [2] 5e 62 [2] 45 2c [2] 78 }

  condition:
    any of them
}