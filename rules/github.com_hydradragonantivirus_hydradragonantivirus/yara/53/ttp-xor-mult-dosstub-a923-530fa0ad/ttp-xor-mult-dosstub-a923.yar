rule TTP_XOR_MULT_DOSStub_a923 {
  strings:
    $key_a923 = { fd 4b [2] 89 53 [2] ce 51 [2] 89 40 [2] c7 4c [2] cb 46 [2] dc 4d [2] c7 03 [2] fa }

  condition:
    any of them
}