rule TTP_XOR_MULT_DOSStub_2b73 {
  strings:
    $key_2b73 = { 7f 1b [2] 0b 03 [2] 4c 01 [2] 0b 10 [2] 45 1c [2] 49 16 [2] 5e 1d [2] 45 53 [2] 78 }

  condition:
    any of them
}