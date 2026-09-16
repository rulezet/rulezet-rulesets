rule TTP_XOR_MULT_DOSStub_d66b {
  strings:
    $key_d66b = { 82 03 [2] f6 1b [2] b1 19 [2] f6 08 [2] b8 04 [2] b4 0e [2] a3 05 [2] b8 4b [2] 85 }

  condition:
    any of them
}