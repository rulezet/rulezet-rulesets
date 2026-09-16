rule TTP_XOR_MULT_DOSStub_f8eb {
  strings:
    $key_f8eb = { ac 83 [2] d8 9b [2] 9f 99 [2] d8 88 [2] 96 84 [2] 9a 8e [2] 8d 85 [2] 96 cb [2] ab }

  condition:
    any of them
}