rule TTP_XOR_MULT_DOSStub_f866 {
  strings:
    $key_f866 = { ac 0e [2] d8 16 [2] 9f 14 [2] d8 05 [2] 96 09 [2] 9a 03 [2] 8d 08 [2] 96 46 [2] ab }

  condition:
    any of them
}