rule TTP_XOR_MULT_DOSStub_136a {
  strings:
    $key_136a = { 47 02 [2] 33 1a [2] 74 18 [2] 33 09 [2] 7d 05 [2] 71 0f [2] 66 04 [2] 7d 4a [2] 40 }

  condition:
    any of them
}