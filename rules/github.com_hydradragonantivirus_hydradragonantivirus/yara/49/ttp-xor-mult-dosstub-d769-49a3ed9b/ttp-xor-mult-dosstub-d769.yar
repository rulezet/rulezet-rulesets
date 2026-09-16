rule TTP_XOR_MULT_DOSStub_d769 {
  strings:
    $key_d769 = { 83 01 [2] f7 19 [2] b0 1b [2] f7 0a [2] b9 06 [2] b5 0c [2] a2 07 [2] b9 49 [2] 84 }

  condition:
    any of them
}