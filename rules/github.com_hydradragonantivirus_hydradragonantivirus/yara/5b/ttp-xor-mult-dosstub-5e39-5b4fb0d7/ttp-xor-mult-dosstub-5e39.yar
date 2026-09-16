rule TTP_XOR_MULT_DOSStub_5e39 {
  strings:
    $key_5e39 = { 0a 51 [2] 7e 49 [2] 39 4b [2] 7e 5a [2] 30 56 [2] 3c 5c [2] 2b 57 [2] 30 19 [2] 0d }

  condition:
    any of them
}