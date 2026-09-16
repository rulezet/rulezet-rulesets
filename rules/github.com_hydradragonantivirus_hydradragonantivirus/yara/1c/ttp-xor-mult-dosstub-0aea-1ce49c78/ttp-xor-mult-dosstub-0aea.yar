rule TTP_XOR_MULT_DOSStub_0aea {
  strings:
    $key_0aea = { 5e 82 [2] 2a 9a [2] 6d 98 [2] 2a 89 [2] 64 85 [2] 68 8f [2] 7f 84 [2] 64 ca [2] 59 }

  condition:
    any of them
}