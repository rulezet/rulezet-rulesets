rule TTP_XOR_MULT_DOSStub_016a {
  strings:
    $key_016a = { 55 02 [2] 21 1a [2] 66 18 [2] 21 09 [2] 6f 05 [2] 63 0f [2] 74 04 [2] 6f 4a [2] 52 }

  condition:
    any of them
}