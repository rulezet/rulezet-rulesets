rule TTP_XOR_MULT_DOSStub_90ed {
  strings:
    $key_90ed = { c4 85 [2] b0 9d [2] f7 9f [2] b0 8e [2] fe 82 [2] f2 88 [2] e5 83 [2] fe cd [2] c3 }

  condition:
    any of them
}