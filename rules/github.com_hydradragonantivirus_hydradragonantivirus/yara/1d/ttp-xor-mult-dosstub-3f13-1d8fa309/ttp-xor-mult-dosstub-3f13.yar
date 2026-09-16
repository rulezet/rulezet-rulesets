rule TTP_XOR_MULT_DOSStub_3f13 {
  strings:
    $key_3f13 = { 6b 7b [2] 1f 63 [2] 58 61 [2] 1f 70 [2] 51 7c [2] 5d 76 [2] 4a 7d [2] 51 33 [2] 6c }

  condition:
    any of them
}