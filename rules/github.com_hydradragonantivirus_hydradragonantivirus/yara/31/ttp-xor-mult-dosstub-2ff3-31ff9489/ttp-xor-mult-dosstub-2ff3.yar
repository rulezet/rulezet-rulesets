rule TTP_XOR_MULT_DOSStub_2ff3 {
  strings:
    $key_2ff3 = { 7b 9b [2] 0f 83 [2] 48 81 [2] 0f 90 [2] 41 9c [2] 4d 96 [2] 5a 9d [2] 41 d3 [2] 7c }

  condition:
    any of them
}