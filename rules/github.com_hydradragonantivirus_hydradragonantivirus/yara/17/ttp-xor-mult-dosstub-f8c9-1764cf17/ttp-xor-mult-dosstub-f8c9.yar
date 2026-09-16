rule TTP_XOR_MULT_DOSStub_f8c9 {
  strings:
    $key_f8c9 = { ac a1 [2] d8 b9 [2] 9f bb [2] d8 aa [2] 96 a6 [2] 9a ac [2] 8d a7 [2] 96 e9 [2] ab }

  condition:
    any of them
}