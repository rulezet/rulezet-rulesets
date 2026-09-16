rule TTP_XOR_MULT_DOSStub_a922 {
  strings:
    $key_a922 = { fd 4a [2] 89 52 [2] ce 50 [2] 89 41 [2] c7 4d [2] cb 47 [2] dc 4c [2] c7 02 [2] fa }

  condition:
    any of them
}