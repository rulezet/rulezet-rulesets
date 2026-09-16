rule TTP_XOR_MULT_DOSStub_a91d {
  strings:
    $key_a91d = { fd 75 [2] 89 6d [2] ce 6f [2] 89 7e [2] c7 72 [2] cb 78 [2] dc 73 [2] c7 3d [2] fa }

  condition:
    any of them
}