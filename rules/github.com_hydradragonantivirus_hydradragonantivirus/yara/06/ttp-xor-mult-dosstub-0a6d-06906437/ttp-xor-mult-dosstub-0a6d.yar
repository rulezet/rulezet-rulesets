rule TTP_XOR_MULT_DOSStub_0a6d {
  strings:
    $key_0a6d = { 5e 05 [2] 2a 1d [2] 6d 1f [2] 2a 0e [2] 64 02 [2] 68 08 [2] 7f 03 [2] 64 4d [2] 59 }

  condition:
    any of them
}