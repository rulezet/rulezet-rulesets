rule TTP_XOR_MULT_DOSStub_1955 {
  strings:
    $key_1955 = { 4d 3d [2] 39 25 [2] 7e 27 [2] 39 36 [2] 77 3a [2] 7b 30 [2] 6c 3b [2] 77 75 [2] 4a }

  condition:
    any of them
}