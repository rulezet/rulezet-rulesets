rule TTP_XOR_MULT_DOSStub_f8ec {
  strings:
    $key_f8ec = { ac 84 [2] d8 9c [2] 9f 9e [2] d8 8f [2] 96 83 [2] 9a 89 [2] 8d 82 [2] 96 cc [2] ab }

  condition:
    any of them
}