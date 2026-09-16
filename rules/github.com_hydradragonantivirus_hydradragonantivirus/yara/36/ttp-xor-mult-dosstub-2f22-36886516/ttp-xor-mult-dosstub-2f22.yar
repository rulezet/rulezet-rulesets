rule TTP_XOR_MULT_DOSStub_2f22 {
  strings:
    $key_2f22 = { 7b 4a [2] 0f 52 [2] 48 50 [2] 0f 41 [2] 41 4d [2] 4d 47 [2] 5a 4c [2] 41 02 [2] 7c }

  condition:
    any of them
}