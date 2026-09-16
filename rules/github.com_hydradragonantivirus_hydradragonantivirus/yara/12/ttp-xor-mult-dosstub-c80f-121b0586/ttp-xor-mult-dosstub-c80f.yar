rule TTP_XOR_MULT_DOSStub_c80f {
  strings:
    $key_c80f = { 9c 67 [2] e8 7f [2] af 7d [2] e8 6c [2] a6 60 [2] aa 6a [2] bd 61 [2] a6 2f [2] 9b }

  condition:
    any of them
}