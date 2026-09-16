rule TTP_XOR_MULT_DOSStub_f80b {
  strings:
    $key_f80b = { ac 63 [2] d8 7b [2] 9f 79 [2] d8 68 [2] 96 64 [2] 9a 6e [2] 8d 65 [2] 96 2b [2] ab }

  condition:
    any of them
}