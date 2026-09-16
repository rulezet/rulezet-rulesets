rule TTP_XOR_MULT_DOSStub_19ef {
  strings:
    $key_19ef = { 4d 87 [2] 39 9f [2] 7e 9d [2] 39 8c [2] 77 80 [2] 7b 8a [2] 6c 81 [2] 77 cf [2] 4a }

  condition:
    any of them
}