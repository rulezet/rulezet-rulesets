rule TTP_XOR_MULT_DOSStub_6523 {
  strings:
    $key_6523 = { 31 4b [2] 45 53 [2] 02 51 [2] 45 40 [2] 0b 4c [2] 07 46 [2] 10 4d [2] 0b 03 [2] 36 }

  condition:
    any of them
}