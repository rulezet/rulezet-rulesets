rule TTP_XOR_MULT_DOSStub_1912 {
  strings:
    $key_1912 = { 4d 7a [2] 39 62 [2] 7e 60 [2] 39 71 [2] 77 7d [2] 7b 77 [2] 6c 7c [2] 77 32 [2] 4a }

  condition:
    any of them
}