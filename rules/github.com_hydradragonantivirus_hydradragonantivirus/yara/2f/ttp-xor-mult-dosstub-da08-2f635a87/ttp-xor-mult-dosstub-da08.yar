rule TTP_XOR_MULT_DOSStub_da08 {
  strings:
    $key_da08 = { 8e 60 [2] fa 78 [2] bd 7a [2] fa 6b [2] b4 67 [2] b8 6d [2] af 66 [2] b4 28 [2] 89 }

  condition:
    any of them
}