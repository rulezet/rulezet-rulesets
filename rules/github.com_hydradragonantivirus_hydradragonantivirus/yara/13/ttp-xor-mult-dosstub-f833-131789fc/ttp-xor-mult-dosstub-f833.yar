rule TTP_XOR_MULT_DOSStub_f833 {
  strings:
    $key_f833 = { ac 5b [2] d8 43 [2] 9f 41 [2] d8 50 [2] 96 5c [2] 9a 56 [2] 8d 5d [2] 96 13 [2] ab }

  condition:
    any of them
}