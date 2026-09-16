rule TTP_XOR_MULT_DOSStub_aced {
  strings:
    $key_aced = { f8 85 [2] 8c 9d [2] cb 9f [2] 8c 8e [2] c2 82 [2] ce 88 [2] d9 83 [2] c2 cd [2] ff }

  condition:
    any of them
}