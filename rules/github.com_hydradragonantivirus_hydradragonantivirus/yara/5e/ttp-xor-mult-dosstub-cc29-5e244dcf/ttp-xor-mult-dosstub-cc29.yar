rule TTP_XOR_MULT_DOSStub_cc29 {
  strings:
    $key_cc29 = { 98 41 [2] ec 59 [2] ab 5b [2] ec 4a [2] a2 46 [2] ae 4c [2] b9 47 [2] a2 09 [2] 9f }

  condition:
    any of them
}