rule TTP_XOR_MULT_DOSStub_3ef3 {
  strings:
    $key_3ef3 = { 6a 9b [2] 1e 83 [2] 59 81 [2] 1e 90 [2] 50 9c [2] 5c 96 [2] 4b 9d [2] 50 d3 [2] 6d }

  condition:
    any of them
}