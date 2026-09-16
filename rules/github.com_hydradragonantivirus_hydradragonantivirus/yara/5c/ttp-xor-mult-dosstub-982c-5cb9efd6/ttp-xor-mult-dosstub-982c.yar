rule TTP_XOR_MULT_DOSStub_982c {
  strings:
    $key_982c = { cc 44 [2] b8 5c [2] ff 5e [2] b8 4f [2] f6 43 [2] fa 49 [2] ed 42 [2] f6 0c [2] cb }

  condition:
    any of them
}