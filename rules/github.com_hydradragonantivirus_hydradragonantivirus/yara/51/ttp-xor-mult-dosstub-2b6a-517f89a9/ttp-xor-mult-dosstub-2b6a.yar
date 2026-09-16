rule TTP_XOR_MULT_DOSStub_2b6a {
  strings:
    $key_2b6a = { 7f 02 [2] 0b 1a [2] 4c 18 [2] 0b 09 [2] 45 05 [2] 49 0f [2] 5e 04 [2] 45 4a [2] 78 }

  condition:
    any of them
}