rule TTP_XOR_MULT_DOSStub_d722 {
  strings:
    $key_d722 = { 83 4a [2] f7 52 [2] b0 50 [2] f7 41 [2] b9 4d [2] b5 47 [2] a2 4c [2] b9 02 [2] 84 }

  condition:
    any of them
}