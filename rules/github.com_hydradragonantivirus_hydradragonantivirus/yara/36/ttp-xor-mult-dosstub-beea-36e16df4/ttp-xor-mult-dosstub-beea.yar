rule TTP_XOR_MULT_DOSStub_beea {
  strings:
    $key_beea = { ea 82 [2] 9e 9a [2] d9 98 [2] 9e 89 [2] d0 85 [2] dc 8f [2] cb 84 [2] d0 ca [2] ed }

  condition:
    any of them
}