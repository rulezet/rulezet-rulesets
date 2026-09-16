rule TTP_XOR_MULT_DOSStub_da23 {
  strings:
    $key_da23 = { 8e 4b [2] fa 53 [2] bd 51 [2] fa 40 [2] b4 4c [2] b8 46 [2] af 4d [2] b4 03 [2] 89 }

  condition:
    any of them
}