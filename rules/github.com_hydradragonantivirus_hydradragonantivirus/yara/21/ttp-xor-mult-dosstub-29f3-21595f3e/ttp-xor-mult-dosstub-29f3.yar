rule TTP_XOR_MULT_DOSStub_29f3 {
  strings:
    $key_29f3 = { 7d 9b [2] 09 83 [2] 4e 81 [2] 09 90 [2] 47 9c [2] 4b 96 [2] 5c 9d [2] 47 d3 [2] 7a }

  condition:
    any of them
}