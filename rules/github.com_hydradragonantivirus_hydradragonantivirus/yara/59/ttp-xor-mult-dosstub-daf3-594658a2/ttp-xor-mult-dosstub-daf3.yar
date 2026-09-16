rule TTP_XOR_MULT_DOSStub_daf3 {
  strings:
    $key_daf3 = { 8e 9b [2] fa 83 [2] bd 81 [2] fa 90 [2] b4 9c [2] b8 96 [2] af 9d [2] b4 d3 [2] 89 }

  condition:
    any of them
}