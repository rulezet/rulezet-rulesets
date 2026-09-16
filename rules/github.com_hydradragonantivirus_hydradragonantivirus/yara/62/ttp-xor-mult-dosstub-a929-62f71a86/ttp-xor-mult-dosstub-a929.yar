rule TTP_XOR_MULT_DOSStub_a929 {
  strings:
    $key_a929 = { fd 41 [2] 89 59 [2] ce 5b [2] 89 4a [2] c7 46 [2] cb 4c [2] dc 47 [2] c7 09 [2] fa }

  condition:
    any of them
}