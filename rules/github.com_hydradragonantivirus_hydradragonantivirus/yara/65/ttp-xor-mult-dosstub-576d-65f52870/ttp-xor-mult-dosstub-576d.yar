rule TTP_XOR_MULT_DOSStub_576d {
  strings:
    $key_576d = { 03 05 [2] 77 1d [2] 30 1f [2] 77 0e [2] 39 02 [2] 35 08 [2] 22 03 [2] 39 4d [2] 04 }

  condition:
    any of them
}