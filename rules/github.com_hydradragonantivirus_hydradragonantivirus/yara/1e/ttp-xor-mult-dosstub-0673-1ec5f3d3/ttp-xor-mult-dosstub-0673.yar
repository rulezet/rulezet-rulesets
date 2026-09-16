rule TTP_XOR_MULT_DOSStub_0673 {
  strings:
    $key_0673 = { 52 1b [2] 26 03 [2] 61 01 [2] 26 10 [2] 68 1c [2] 64 16 [2] 73 1d [2] 68 53 [2] 55 }

  condition:
    any of them
}