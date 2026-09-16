rule TTP_XOR_MULT_DOSStub_9123 {
  strings:
    $key_9123 = { c5 4b [2] b1 53 [2] f6 51 [2] b1 40 [2] ff 4c [2] f3 46 [2] e4 4d [2] ff 03 [2] c2 }

  condition:
    any of them
}