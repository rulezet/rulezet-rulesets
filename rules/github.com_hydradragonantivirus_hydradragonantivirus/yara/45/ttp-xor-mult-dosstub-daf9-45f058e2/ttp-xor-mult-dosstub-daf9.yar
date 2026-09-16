rule TTP_XOR_MULT_DOSStub_daf9 {
  strings:
    $key_daf9 = { 8e 91 [2] fa 89 [2] bd 8b [2] fa 9a [2] b4 96 [2] b8 9c [2] af 97 [2] b4 d9 [2] 89 }

  condition:
    any of them
}