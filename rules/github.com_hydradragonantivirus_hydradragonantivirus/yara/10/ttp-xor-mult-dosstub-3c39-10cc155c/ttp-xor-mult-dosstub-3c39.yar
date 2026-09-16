rule TTP_XOR_MULT_DOSStub_3c39 {
  strings:
    $key_3c39 = { 68 51 [2] 1c 49 [2] 5b 4b [2] 1c 5a [2] 52 56 [2] 5e 5c [2] 49 57 [2] 52 19 [2] 6f }

  condition:
    any of them
}