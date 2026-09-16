rule TTP_XOR_MULT_DOSStub_5ef3 {
  strings:
    $key_5ef3 = { 0a 9b [2] 7e 83 [2] 39 81 [2] 7e 90 [2] 30 9c [2] 3c 96 [2] 2b 9d [2] 30 d3 [2] 0d }

  condition:
    any of them
}