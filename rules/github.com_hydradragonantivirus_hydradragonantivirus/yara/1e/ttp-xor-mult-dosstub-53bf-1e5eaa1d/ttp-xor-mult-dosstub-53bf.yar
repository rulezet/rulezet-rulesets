rule TTP_XOR_MULT_DOSStub_53bf {
  strings:
    $key_53bf = { 07 d7 [2] 73 cf [2] 34 cd [2] 73 dc [2] 3d d0 [2] 31 da [2] 26 d1 [2] 3d 9f [2] 00 }

  condition:
    any of them
}