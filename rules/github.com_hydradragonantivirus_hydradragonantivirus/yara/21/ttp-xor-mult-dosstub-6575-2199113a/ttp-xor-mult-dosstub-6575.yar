rule TTP_XOR_MULT_DOSStub_6575 {
  strings:
    $key_6575 = { 31 1d [2] 45 05 [2] 02 07 [2] 45 16 [2] 0b 1a [2] 07 10 [2] 10 1b [2] 0b 55 [2] 36 }

  condition:
    any of them
}