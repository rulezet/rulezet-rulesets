rule TTP_XOR_MULT_DOSStub_982d {
  strings:
    $key_982d = { cc 45 [2] b8 5d [2] ff 5f [2] b8 4e [2] f6 42 [2] fa 48 [2] ed 43 [2] f6 0d [2] cb }

  condition:
    any of them
}