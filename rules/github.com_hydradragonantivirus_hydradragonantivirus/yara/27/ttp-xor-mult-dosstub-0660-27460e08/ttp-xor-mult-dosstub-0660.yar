rule TTP_XOR_MULT_DOSStub_0660 {
  strings:
    $key_0660 = { 52 08 [2] 26 10 [2] 61 12 [2] 26 03 [2] 68 0f [2] 64 05 [2] 73 0e [2] 68 40 [2] 55 }

  condition:
    any of them
}