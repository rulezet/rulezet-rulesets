rule TTP_XOR_MULT_DOSStub_1935 {
  strings:
    $key_1935 = { 4d 5d [2] 39 45 [2] 7e 47 [2] 39 56 [2] 77 5a [2] 7b 50 [2] 6c 5b [2] 77 15 [2] 4a }

  condition:
    any of them
}