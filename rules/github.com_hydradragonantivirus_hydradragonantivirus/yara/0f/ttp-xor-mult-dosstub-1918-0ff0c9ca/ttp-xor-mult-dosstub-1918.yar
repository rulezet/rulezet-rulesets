rule TTP_XOR_MULT_DOSStub_1918 {
  strings:
    $key_1918 = { 4d 70 [2] 39 68 [2] 7e 6a [2] 39 7b [2] 77 77 [2] 7b 7d [2] 6c 76 [2] 77 38 [2] 4a }

  condition:
    any of them
}