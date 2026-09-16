rule TTP_XOR_MULT_DOSStub_a92d {
  strings:
    $key_a92d = { fd 45 [2] 89 5d [2] ce 5f [2] 89 4e [2] c7 42 [2] cb 48 [2] dc 43 [2] c7 0d [2] fa }

  condition:
    any of them
}