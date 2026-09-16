rule TTP_XOR_MULT_DOSStub_6aea {
  strings:
    $key_6aea = { 3e 82 [2] 4a 9a [2] 0d 98 [2] 4a 89 [2] 04 85 [2] 08 8f [2] 1f 84 [2] 04 ca [2] 39 }

  condition:
    any of them
}