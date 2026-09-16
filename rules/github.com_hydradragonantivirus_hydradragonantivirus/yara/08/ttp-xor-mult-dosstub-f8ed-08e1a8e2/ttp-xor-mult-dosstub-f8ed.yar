rule TTP_XOR_MULT_DOSStub_f8ed {
  strings:
    $key_f8ed = { ac 85 [2] d8 9d [2] 9f 9f [2] d8 8e [2] 96 82 [2] 9a 88 [2] 8d 83 [2] 96 cd [2] ab }

  condition:
    any of them
}