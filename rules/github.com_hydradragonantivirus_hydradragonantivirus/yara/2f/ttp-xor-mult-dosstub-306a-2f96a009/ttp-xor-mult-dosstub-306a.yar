rule TTP_XOR_MULT_DOSStub_306a {
  strings:
    $key_306a = { 64 02 [2] 10 1a [2] 57 18 [2] 10 09 [2] 5e 05 [2] 52 0f [2] 45 04 [2] 5e 4a [2] 63 }

  condition:
    any of them
}