rule TTP_XOR_MULT_DOSStub_dafd {
  strings:
    $key_dafd = { 8e 95 [2] fa 8d [2] bd 8f [2] fa 9e [2] b4 92 [2] b8 98 [2] af 93 [2] b4 dd [2] 89 }

  condition:
    any of them
}