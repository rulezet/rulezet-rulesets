rule TTP_XOR_MULT_DOSStub_985b {
  strings:
    $key_985b = { cc 33 [2] b8 2b [2] ff 29 [2] b8 38 [2] f6 34 [2] fa 3e [2] ed 35 [2] f6 7b [2] cb }

  condition:
    any of them
}