rule TTP_XOR_MULT_DOSStub_a9ed {
  strings:
    $key_a9ed = { fd 85 [2] 89 9d [2] ce 9f [2] 89 8e [2] c7 82 [2] cb 88 [2] dc 83 [2] c7 cd [2] fa }

  condition:
    any of them
}