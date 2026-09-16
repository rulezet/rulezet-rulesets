rule TTP_XOR_MULT_DOSStub_2b74 {
  strings:
    $key_2b74 = { 7f 1c [2] 0b 04 [2] 4c 06 [2] 0b 17 [2] 45 1b [2] 49 11 [2] 5e 1a [2] 45 54 [2] 78 }

  condition:
    any of them
}