rule TTP_XOR_MULT_DOSStub_0929 {
  strings:
    $key_0929 = { 5d 41 [2] 29 59 [2] 6e 5b [2] 29 4a [2] 67 46 [2] 6b 4c [2] 7c 47 [2] 67 09 [2] 5a }

  condition:
    any of them
}