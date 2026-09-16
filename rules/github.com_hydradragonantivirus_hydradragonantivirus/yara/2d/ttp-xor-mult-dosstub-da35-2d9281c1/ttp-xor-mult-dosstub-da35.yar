rule TTP_XOR_MULT_DOSStub_da35 {
  strings:
    $key_da35 = { 8e 5d [2] fa 45 [2] bd 47 [2] fa 56 [2] b4 5a [2] b8 50 [2] af 5b [2] b4 15 [2] 89 }

  condition:
    any of them
}