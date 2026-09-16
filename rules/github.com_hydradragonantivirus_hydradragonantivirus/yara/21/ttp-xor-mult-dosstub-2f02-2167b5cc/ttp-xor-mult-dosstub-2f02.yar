rule TTP_XOR_MULT_DOSStub_2f02 {
  strings:
    $key_2f02 = { 7b 6a [2] 0f 72 [2] 48 70 [2] 0f 61 [2] 41 6d [2] 4d 67 [2] 5a 6c [2] 41 22 [2] 7c }

  condition:
    any of them
}