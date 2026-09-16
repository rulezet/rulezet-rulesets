rule TTP_XOR_MULT_DOSStub_d723 {
  strings:
    $key_d723 = { 83 4b [2] f7 53 [2] b0 51 [2] f7 40 [2] b9 4c [2] b5 46 [2] a2 4d [2] b9 03 [2] 84 }

  condition:
    any of them
}