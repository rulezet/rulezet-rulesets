rule TTP_XOR_MULT_DOSStub_0f23 {
  strings:
    $key_0f23 = { 5b 4b [2] 2f 53 [2] 68 51 [2] 2f 40 [2] 61 4c [2] 6d 46 [2] 7a 4d [2] 61 03 [2] 5c }

  condition:
    any of them
}