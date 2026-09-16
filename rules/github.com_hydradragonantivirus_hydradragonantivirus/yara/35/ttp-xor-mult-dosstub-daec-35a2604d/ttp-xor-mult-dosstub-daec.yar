rule TTP_XOR_MULT_DOSStub_daec {
  strings:
    $key_daec = { 8e 84 [2] fa 9c [2] bd 9e [2] fa 8f [2] b4 83 [2] b8 89 [2] af 82 [2] b4 cc [2] 89 }

  condition:
    any of them
}