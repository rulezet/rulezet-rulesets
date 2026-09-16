rule TTP_XOR_MULT_DOSStub_623c {
  strings:
    $key_623c = { 36 54 [2] 42 4c [2] 05 4e [2] 42 5f [2] 0c 53 [2] 00 59 [2] 17 52 [2] 0c 1c [2] 31 }

  condition:
    any of them
}