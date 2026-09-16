rule TTP_XOR_MULT_DOSStub_3b6a {
  strings:
    $key_3b6a = { 6f 02 [2] 1b 1a [2] 5c 18 [2] 1b 09 [2] 55 05 [2] 59 0f [2] 4e 04 [2] 55 4a [2] 68 }

  condition:
    any of them
}