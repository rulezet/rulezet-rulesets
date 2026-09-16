rule TTP_XOR_MULT_DOSStub_3bea {
  strings:
    $key_3bea = { 6f 82 [2] 1b 9a [2] 5c 98 [2] 1b 89 [2] 55 85 [2] 59 8f [2] 4e 84 [2] 55 ca [2] 68 }

  condition:
    any of them
}