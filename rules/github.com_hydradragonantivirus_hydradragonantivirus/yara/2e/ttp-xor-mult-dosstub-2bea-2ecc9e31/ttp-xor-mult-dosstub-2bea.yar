rule TTP_XOR_MULT_DOSStub_2bea {
  strings:
    $key_2bea = { 7f 82 [2] 0b 9a [2] 4c 98 [2] 0b 89 [2] 45 85 [2] 49 8f [2] 5e 84 [2] 45 ca [2] 78 }

  condition:
    any of them
}