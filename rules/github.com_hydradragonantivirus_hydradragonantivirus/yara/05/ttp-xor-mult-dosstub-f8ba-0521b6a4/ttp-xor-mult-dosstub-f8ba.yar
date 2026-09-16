rule TTP_XOR_MULT_DOSStub_f8ba {
  strings:
    $key_f8ba = { ac d2 [2] d8 ca [2] 9f c8 [2] d8 d9 [2] 96 d5 [2] 9a df [2] 8d d4 [2] 96 9a [2] ab }

  condition:
    any of them
}