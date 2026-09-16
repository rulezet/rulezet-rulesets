rule TTP_XOR_MULT_DOSStub_2f6d {
  strings:
    $key_2f6d = { 7b 05 [2] 0f 1d [2] 48 1f [2] 0f 0e [2] 41 02 [2] 4d 08 [2] 5a 03 [2] 41 4d [2] 7c }

  condition:
    any of them
}