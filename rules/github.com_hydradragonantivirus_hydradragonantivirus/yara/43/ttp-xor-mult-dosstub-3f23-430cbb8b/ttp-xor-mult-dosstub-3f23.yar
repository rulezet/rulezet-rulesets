rule TTP_XOR_MULT_DOSStub_3f23 {
  strings:
    $key_3f23 = { 6b 4b [2] 1f 53 [2] 58 51 [2] 1f 40 [2] 51 4c [2] 5d 46 [2] 4a 4d [2] 51 03 [2] 6c }

  condition:
    any of them
}