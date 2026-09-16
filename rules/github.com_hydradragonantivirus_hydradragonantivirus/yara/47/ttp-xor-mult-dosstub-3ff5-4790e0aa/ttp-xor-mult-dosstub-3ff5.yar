rule TTP_XOR_MULT_DOSStub_3ff5 {
  strings:
    $key_3ff5 = { 6b 9d [2] 1f 85 [2] 58 87 [2] 1f 96 [2] 51 9a [2] 5d 90 [2] 4a 9b [2] 51 d5 [2] 6c }

  condition:
    any of them
}