rule TTP_XOR_MULT_DOSStub_a91a {
  strings:
    $key_a91a = { fd 72 [2] 89 6a [2] ce 68 [2] 89 79 [2] c7 75 [2] cb 7f [2] dc 74 [2] c7 3a [2] fa }

  condition:
    any of them
}