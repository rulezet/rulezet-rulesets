rule TTP_XOR_MULT_DOSStub_6a73 {
  strings:
    $key_6a73 = { 3e 1b [2] 4a 03 [2] 0d 01 [2] 4a 10 [2] 04 1c [2] 08 16 [2] 1f 1d [2] 04 53 [2] 39 }

  condition:
    any of them
}