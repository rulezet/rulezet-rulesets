rule TTP_XOR_MULT_DOSStub_da53 {
  strings:
    $key_da53 = { 8e 3b [2] fa 23 [2] bd 21 [2] fa 30 [2] b4 3c [2] b8 36 [2] af 3d [2] b4 73 [2] 89 }

  condition:
    any of them
}