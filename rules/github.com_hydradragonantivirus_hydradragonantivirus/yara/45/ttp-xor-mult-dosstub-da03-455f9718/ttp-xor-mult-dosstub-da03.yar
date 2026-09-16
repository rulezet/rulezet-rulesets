rule TTP_XOR_MULT_DOSStub_da03 {
  strings:
    $key_da03 = { 8e 6b [2] fa 73 [2] bd 71 [2] fa 60 [2] b4 6c [2] b8 66 [2] af 6d [2] b4 23 [2] 89 }

  condition:
    any of them
}