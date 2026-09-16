rule TTP_XOR_MULT_DOSStub_a92b {
  strings:
    $key_a92b = { fd 43 [2] 89 5b [2] ce 59 [2] 89 48 [2] c7 44 [2] cb 4e [2] dc 45 [2] c7 0b [2] fa }

  condition:
    any of them
}