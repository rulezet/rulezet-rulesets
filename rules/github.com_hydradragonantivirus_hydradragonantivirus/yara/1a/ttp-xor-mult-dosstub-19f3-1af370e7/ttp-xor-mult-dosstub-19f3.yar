rule TTP_XOR_MULT_DOSStub_19f3 {
  strings:
    $key_19f3 = { 4d 9b [2] 39 83 [2] 7e 81 [2] 39 90 [2] 77 9c [2] 7b 96 [2] 6c 9d [2] 77 d3 [2] 4a }

  condition:
    any of them
}