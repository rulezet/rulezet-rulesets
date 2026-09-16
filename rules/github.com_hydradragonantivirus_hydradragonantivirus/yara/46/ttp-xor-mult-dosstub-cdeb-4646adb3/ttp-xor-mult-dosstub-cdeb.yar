rule TTP_XOR_MULT_DOSStub_cdeb {
  strings:
    $key_cdeb = { 99 83 [2] ed 9b [2] aa 99 [2] ed 88 [2] a3 84 [2] af 8e [2] b8 85 [2] a3 cb [2] 9e }

  condition:
    any of them
}