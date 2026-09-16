rule TTP_XOR_MULT_DOSStub_6529 {
  strings:
    $key_6529 = { 31 41 [2] 45 59 [2] 02 5b [2] 45 4a [2] 0b 46 [2] 07 4c [2] 10 47 [2] 0b 09 [2] 36 }

  condition:
    any of them
}