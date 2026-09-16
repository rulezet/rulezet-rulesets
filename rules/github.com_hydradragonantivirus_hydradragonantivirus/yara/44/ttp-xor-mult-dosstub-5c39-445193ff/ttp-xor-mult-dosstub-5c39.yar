rule TTP_XOR_MULT_DOSStub_5c39 {
  strings:
    $key_5c39 = { 08 51 [2] 7c 49 [2] 3b 4b [2] 7c 5a [2] 32 56 [2] 3e 5c [2] 29 57 [2] 32 19 [2] 0f }

  condition:
    any of them
}