rule TTP_XOR_MULT_DOSStub_f88a {
  strings:
    $key_f88a = { ac e2 [2] d8 fa [2] 9f f8 [2] d8 e9 [2] 96 e5 [2] 9a ef [2] 8d e4 [2] 96 aa [2] ab }

  condition:
    any of them
}