rule TTP_XOR_MULT_DOSStub_6cef {
  strings:
    $key_6cef = { 38 87 [2] 4c 9f [2] 0b 9d [2] 4c 8c [2] 02 80 [2] 0e 8a [2] 19 81 [2] 02 cf [2] 3f }

  condition:
    any of them
}