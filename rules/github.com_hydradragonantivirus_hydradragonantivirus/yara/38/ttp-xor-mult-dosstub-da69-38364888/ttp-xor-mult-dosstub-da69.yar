rule TTP_XOR_MULT_DOSStub_da69 {
  strings:
    $key_da69 = { 8e 01 [2] fa 19 [2] bd 1b [2] fa 0a [2] b4 06 [2] b8 0c [2] af 07 [2] b4 49 [2] 89 }

  condition:
    any of them
}