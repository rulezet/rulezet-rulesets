rule TTP_XOR_MULT_DOSStub_d623 {
  strings:
    $key_d623 = { 82 4b [2] f6 53 [2] b1 51 [2] f6 40 [2] b8 4c [2] b4 46 [2] a3 4d [2] b8 03 [2] 85 }

  condition:
    any of them
}