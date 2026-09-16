rule TTP_XOR_MULT_DOSStub_4cef {
  strings:
    $key_4cef = { 18 87 [2] 6c 9f [2] 2b 9d [2] 6c 8c [2] 22 80 [2] 2e 8a [2] 39 81 [2] 22 cf [2] 1f }

  condition:
    any of them
}