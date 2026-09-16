rule TTP_XOR_MULT_DOSStub_c98c {
  strings:
    $key_c98c = { 9d e4 [2] e9 fc [2] ae fe [2] e9 ef [2] a7 e3 [2] ab e9 [2] bc e2 [2] a7 ac [2] 9a }

  condition:
    any of them
}