rule TTP_XOR_MULT_DOSStub_daf5 {
  strings:
    $key_daf5 = { 8e 9d [2] fa 85 [2] bd 87 [2] fa 96 [2] b4 9a [2] b8 90 [2] af 9b [2] b4 d5 [2] 89 }

  condition:
    any of them
}