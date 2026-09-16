rule TTP_XOR_MULT_DOSStub_2901 {
  strings:
    $key_2901 = { 7d 69 [2] 09 71 [2] 4e 73 [2] 09 62 [2] 47 6e [2] 4b 64 [2] 5c 6f [2] 47 21 [2] 7a }

  condition:
    any of them
}