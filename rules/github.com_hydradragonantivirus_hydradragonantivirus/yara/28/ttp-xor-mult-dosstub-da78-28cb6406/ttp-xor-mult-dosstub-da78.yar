rule TTP_XOR_MULT_DOSStub_da78 {
  strings:
    $key_da78 = { 8e 10 [2] fa 08 [2] bd 0a [2] fa 1b [2] b4 17 [2] b8 1d [2] af 16 [2] b4 58 [2] 89 }

  condition:
    any of them
}