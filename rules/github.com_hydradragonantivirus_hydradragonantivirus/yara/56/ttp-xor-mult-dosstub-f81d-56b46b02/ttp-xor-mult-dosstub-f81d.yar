rule TTP_XOR_MULT_DOSStub_f81d {
  strings:
    $key_f81d = { ac 75 [2] d8 6d [2] 9f 6f [2] d8 7e [2] 96 72 [2] 9a 78 [2] 8d 73 [2] 96 3d [2] ab }

  condition:
    any of them
}