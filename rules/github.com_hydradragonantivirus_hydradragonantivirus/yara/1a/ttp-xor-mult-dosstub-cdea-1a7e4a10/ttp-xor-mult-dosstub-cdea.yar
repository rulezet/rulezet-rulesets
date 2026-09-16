rule TTP_XOR_MULT_DOSStub_cdea {
  strings:
    $key_cdea = { 99 82 [2] ed 9a [2] aa 98 [2] ed 89 [2] a3 85 [2] af 8f [2] b8 84 [2] a3 ca [2] 9e }

  condition:
    any of them
}