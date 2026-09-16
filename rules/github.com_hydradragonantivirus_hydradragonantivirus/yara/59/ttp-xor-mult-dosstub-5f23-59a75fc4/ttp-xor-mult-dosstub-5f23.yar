rule TTP_XOR_MULT_DOSStub_5f23 {
  strings:
    $key_5f23 = { 0b 4b [2] 7f 53 [2] 38 51 [2] 7f 40 [2] 31 4c [2] 3d 46 [2] 2a 4d [2] 31 03 [2] 0c }

  condition:
    any of them
}