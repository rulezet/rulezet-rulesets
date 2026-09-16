rule TTP_XOR_MULT_DOSStub_f86a {
  strings:
    $key_f86a = { ac 02 [2] d8 1a [2] 9f 18 [2] d8 09 [2] 96 05 [2] 9a 0f [2] 8d 04 [2] 96 4a [2] ab }

  condition:
    any of them
}