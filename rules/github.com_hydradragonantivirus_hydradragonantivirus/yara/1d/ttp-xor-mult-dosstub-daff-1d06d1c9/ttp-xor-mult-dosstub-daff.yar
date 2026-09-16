rule TTP_XOR_MULT_DOSStub_daff {
  strings:
    $key_daff = { 8e 97 [2] fa 8f [2] bd 8d [2] fa 9c [2] b4 90 [2] b8 9a [2] af 91 [2] b4 df [2] 89 }

  condition:
    any of them
}