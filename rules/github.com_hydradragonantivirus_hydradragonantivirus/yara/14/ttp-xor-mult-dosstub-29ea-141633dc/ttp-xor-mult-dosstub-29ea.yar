rule TTP_XOR_MULT_DOSStub_29ea {
  strings:
    $key_29ea = { 7d 82 [2] 09 9a [2] 4e 98 [2] 09 89 [2] 47 85 [2] 4b 8f [2] 5c 84 [2] 47 ca [2] 7a }

  condition:
    any of them
}