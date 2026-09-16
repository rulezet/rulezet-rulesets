rule TTP_XOR_MULT_DOSStub_f80d {
  strings:
    $key_f80d = { ac 65 [2] d8 7d [2] 9f 7f [2] d8 6e [2] 96 62 [2] 9a 68 [2] 8d 63 [2] 96 2d [2] ab }

  condition:
    any of them
}