rule TTP_XOR_MULT_DOSStub_6f23 {
  strings:
    $key_6f23 = { 3b 4b [2] 4f 53 [2] 08 51 [2] 4f 40 [2] 01 4c [2] 0d 46 [2] 1a 4d [2] 01 03 [2] 3c }

  condition:
    any of them
}