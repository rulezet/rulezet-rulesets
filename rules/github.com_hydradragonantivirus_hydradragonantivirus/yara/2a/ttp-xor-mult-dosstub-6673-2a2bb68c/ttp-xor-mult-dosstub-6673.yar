rule TTP_XOR_MULT_DOSStub_6673 {
  strings:
    $key_6673 = { 32 1b [2] 46 03 [2] 01 01 [2] 46 10 [2] 08 1c [2] 04 16 [2] 13 1d [2] 08 53 [2] 35 }

  condition:
    any of them
}