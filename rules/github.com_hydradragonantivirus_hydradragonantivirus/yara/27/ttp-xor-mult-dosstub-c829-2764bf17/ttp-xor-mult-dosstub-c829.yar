rule TTP_XOR_MULT_DOSStub_c829 {
  strings:
    $key_c829 = { 9c 41 [2] e8 59 [2] af 5b [2] e8 4a [2] a6 46 [2] aa 4c [2] bd 47 [2] a6 09 [2] 9b }

  condition:
    any of them
}