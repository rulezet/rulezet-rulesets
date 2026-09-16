rule TTP_XOR_MULT_DOSStub_c803 {
  strings:
    $key_c803 = { 9c 6b [2] e8 73 [2] af 71 [2] e8 60 [2] a6 6c [2] aa 66 [2] bd 6d [2] a6 23 [2] 9b }

  condition:
    any of them
}