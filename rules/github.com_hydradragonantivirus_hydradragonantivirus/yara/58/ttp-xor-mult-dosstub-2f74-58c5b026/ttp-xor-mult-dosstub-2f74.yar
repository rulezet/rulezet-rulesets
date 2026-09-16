rule TTP_XOR_MULT_DOSStub_2f74 {
  strings:
    $key_2f74 = { 7b 1c [2] 0f 04 [2] 48 06 [2] 0f 17 [2] 41 1b [2] 4d 11 [2] 5a 1a [2] 41 54 [2] 7c }

  condition:
    any of them
}