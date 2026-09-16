rule TTP_XOR_MULT_DOSStub_7e39 {
  strings:
    $key_7e39 = { 2a 51 [2] 5e 49 [2] 19 4b [2] 5e 5a [2] 10 56 [2] 1c 5c [2] 0b 57 [2] 10 19 [2] 2d }

  condition:
    any of them
}