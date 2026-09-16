rule TTP_XOR_MULT_DOSStub_000c {
  strings:
    $key_000c = { 54 64 [2] 20 7c [2] 67 7e [2] 20 6f [2] 6e 63 [2] 62 69 [2] 75 62 [2] 6e 2c [2] 53 }

  condition:
    any of them
}