rule TTP_XOR_MULT_DOSStub_a93c {
  strings:
    $key_a93c = { fd 54 [2] 89 4c [2] ce 4e [2] 89 5f [2] c7 53 [2] cb 59 [2] dc 52 [2] c7 1c [2] fa }

  condition:
    any of them
}