rule TTP_XOR_MULT_DOSStub_daeb {
  strings:
    $key_daeb = { 8e 83 [2] fa 9b [2] bd 99 [2] fa 88 [2] b4 84 [2] b8 8e [2] af 85 [2] b4 cb [2] 89 }

  condition:
    any of them
}