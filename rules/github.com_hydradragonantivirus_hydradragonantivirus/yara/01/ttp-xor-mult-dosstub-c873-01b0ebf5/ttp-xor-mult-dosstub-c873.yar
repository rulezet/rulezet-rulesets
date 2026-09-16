rule TTP_XOR_MULT_DOSStub_c873 {
  strings:
    $key_c873 = { 9c 1b [2] e8 03 [2] af 01 [2] e8 10 [2] a6 1c [2] aa 16 [2] bd 1d [2] a6 53 [2] 9b }

  condition:
    any of them
}