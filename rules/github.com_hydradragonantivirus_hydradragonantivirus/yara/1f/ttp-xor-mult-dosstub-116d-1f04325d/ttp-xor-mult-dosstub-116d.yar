rule TTP_XOR_MULT_DOSStub_116d {
  strings:
    $key_116d = { 45 05 [2] 31 1d [2] 76 1f [2] 31 0e [2] 7f 02 [2] 73 08 [2] 64 03 [2] 7f 4d [2] 42 }

  condition:
    any of them
}