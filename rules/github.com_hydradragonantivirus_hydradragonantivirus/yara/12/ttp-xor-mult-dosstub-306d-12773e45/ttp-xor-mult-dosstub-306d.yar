rule TTP_XOR_MULT_DOSStub_306d {
  strings:
    $key_306d = { 64 05 [2] 10 1d [2] 57 1f [2] 10 0e [2] 5e 02 [2] 52 08 [2] 45 03 [2] 5e 4d [2] 63 }

  condition:
    any of them
}