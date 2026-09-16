rule TTP_XOR_MULT_DOSStub_6bea {
  strings:
    $key_6bea = { 3f 82 [2] 4b 9a [2] 0c 98 [2] 4b 89 [2] 05 85 [2] 09 8f [2] 1e 84 [2] 05 ca [2] 38 }

  condition:
    any of them
}