rule TTP_XOR_MULT_DOSStub_c98a {
  strings:
    $key_c98a = { 9d e2 [2] e9 fa [2] ae f8 [2] e9 e9 [2] a7 e5 [2] ab ef [2] bc e4 [2] a7 aa [2] 9a }

  condition:
    any of them
}