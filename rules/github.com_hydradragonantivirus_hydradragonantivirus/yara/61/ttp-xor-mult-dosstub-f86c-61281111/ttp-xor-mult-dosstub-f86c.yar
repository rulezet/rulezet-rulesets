rule TTP_XOR_MULT_DOSStub_f86c {
  strings:
    $key_f86c = { ac 04 [2] d8 1c [2] 9f 1e [2] d8 0f [2] 96 03 [2] 9a 09 [2] 8d 02 [2] 96 4c [2] ab }

  condition:
    any of them
}