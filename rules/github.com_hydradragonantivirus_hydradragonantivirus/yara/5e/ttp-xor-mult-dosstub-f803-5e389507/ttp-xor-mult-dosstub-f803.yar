rule TTP_XOR_MULT_DOSStub_f803 {
  strings:
    $key_f803 = { ac 6b [2] d8 73 [2] 9f 71 [2] d8 60 [2] 96 6c [2] 9a 66 [2] 8d 6d [2] 96 23 [2] ab }

  condition:
    any of them
}