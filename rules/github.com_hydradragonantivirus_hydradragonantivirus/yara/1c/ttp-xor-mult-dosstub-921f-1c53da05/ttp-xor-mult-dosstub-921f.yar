rule TTP_XOR_MULT_DOSStub_921f {
  strings:
    $key_921f = { c6 77 [2] b2 6f [2] f5 6d [2] b2 7c [2] fc 70 [2] f0 7a [2] e7 71 [2] fc 3f [2] c1 }

  condition:
    any of them
}