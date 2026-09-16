rule TTP_XOR_MULT_DOSStub_a91c {
  strings:
    $key_a91c = { fd 74 [2] 89 6c [2] ce 6e [2] 89 7f [2] c7 73 [2] cb 79 [2] dc 72 [2] c7 3c [2] fa }

  condition:
    any of them
}