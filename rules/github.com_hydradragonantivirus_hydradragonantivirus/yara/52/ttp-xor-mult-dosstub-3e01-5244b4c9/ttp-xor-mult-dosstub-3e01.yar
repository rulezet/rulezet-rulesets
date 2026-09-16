rule TTP_XOR_MULT_DOSStub_3e01 {
  strings:
    $key_3e01 = { 6a 69 [2] 1e 71 [2] 59 73 [2] 1e 62 [2] 50 6e [2] 5c 64 [2] 4b 6f [2] 50 21 [2] 6d }

  condition:
    any of them
}