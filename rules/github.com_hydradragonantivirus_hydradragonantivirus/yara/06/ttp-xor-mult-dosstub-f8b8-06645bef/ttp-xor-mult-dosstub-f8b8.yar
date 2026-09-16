rule TTP_XOR_MULT_DOSStub_f8b8 {
  strings:
    $key_f8b8 = { ac d0 [2] d8 c8 [2] 9f ca [2] d8 db [2] 96 d7 [2] 9a dd [2] 8d d6 [2] 96 98 [2] ab }

  condition:
    any of them
}