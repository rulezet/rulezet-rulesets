rule TTP_XOR_MULT_DOSStub_986a {
  strings:
    $key_986a = { cc 02 [2] b8 1a [2] ff 18 [2] b8 09 [2] f6 05 [2] fa 0f [2] ed 04 [2] f6 4a [2] cb }

  condition:
    any of them
}