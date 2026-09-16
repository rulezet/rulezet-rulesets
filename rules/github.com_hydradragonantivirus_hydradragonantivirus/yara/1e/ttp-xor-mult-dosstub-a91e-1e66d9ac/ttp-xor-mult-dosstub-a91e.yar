rule TTP_XOR_MULT_DOSStub_a91e {
  strings:
    $key_a91e = { fd 76 [2] 89 6e [2] ce 6c [2] 89 7d [2] c7 71 [2] cb 7b [2] dc 70 [2] c7 3e [2] fa }

  condition:
    any of them
}