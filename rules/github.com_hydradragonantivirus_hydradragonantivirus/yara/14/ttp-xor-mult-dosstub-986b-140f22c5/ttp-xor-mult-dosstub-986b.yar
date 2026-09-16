rule TTP_XOR_MULT_DOSStub_986b {
  strings:
    $key_986b = { cc 03 [2] b8 1b [2] ff 19 [2] b8 08 [2] f6 04 [2] fa 0e [2] ed 05 [2] f6 4b [2] cb }

  condition:
    any of them
}