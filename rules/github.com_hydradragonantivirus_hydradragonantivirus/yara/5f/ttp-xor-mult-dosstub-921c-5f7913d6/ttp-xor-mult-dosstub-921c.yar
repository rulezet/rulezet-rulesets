rule TTP_XOR_MULT_DOSStub_921c {
  strings:
    $key_921c = { c6 74 [2] b2 6c [2] f5 6e [2] b2 7f [2] fc 73 [2] f0 79 [2] e7 72 [2] fc 3c [2] c1 }

  condition:
    any of them
}