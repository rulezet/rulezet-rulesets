rule TTP_XOR_MULT_DOSStub_cdff {
  strings:
    $key_cdff = { 99 97 [2] ed 8f [2] aa 8d [2] ed 9c [2] a3 90 [2] af 9a [2] b8 91 [2] a3 df [2] 9e }

  condition:
    any of them
}