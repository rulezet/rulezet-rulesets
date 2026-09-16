rule TTP_XOR_MULT_DOSStub_921e {
  strings:
    $key_921e = { c6 76 [2] b2 6e [2] f5 6c [2] b2 7d [2] fc 71 [2] f0 7b [2] e7 70 [2] fc 3e [2] c1 }

  condition:
    any of them
}