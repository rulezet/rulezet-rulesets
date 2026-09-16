rule TTP_XOR_MULT_DOSStub_a935 {
  strings:
    $key_a935 = { fd 5d [2] 89 45 [2] ce 47 [2] 89 56 [2] c7 5a [2] cb 50 [2] dc 5b [2] c7 15 [2] fa }

  condition:
    any of them
}