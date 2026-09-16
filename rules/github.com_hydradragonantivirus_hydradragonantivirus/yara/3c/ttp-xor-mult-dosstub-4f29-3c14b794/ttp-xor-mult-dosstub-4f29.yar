rule TTP_XOR_MULT_DOSStub_4f29 {
  strings:
    $key_4f29 = { 1b 41 [2] 6f 59 [2] 28 5b [2] 6f 4a [2] 21 46 [2] 2d 4c [2] 3a 47 [2] 21 09 [2] 1c }

  condition:
    any of them
}