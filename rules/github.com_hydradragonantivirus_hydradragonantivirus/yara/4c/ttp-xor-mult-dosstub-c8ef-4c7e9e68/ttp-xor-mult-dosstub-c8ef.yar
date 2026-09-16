rule TTP_XOR_MULT_DOSStub_c8ef {
  strings:
    $key_c8ef = { 9c 87 [2] e8 9f [2] af 9d [2] e8 8c [2] a6 80 [2] aa 8a [2] bd 81 [2] a6 cf [2] 9b }

  condition:
    any of them
}