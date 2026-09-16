rule TTP_XOR_MULT_DOSStub_716a {
  strings:
    $key_716a = { 25 02 [2] 51 1a [2] 16 18 [2] 51 09 [2] 1f 05 [2] 13 0f [2] 04 04 [2] 1f 4a [2] 22 }

  condition:
    any of them
}