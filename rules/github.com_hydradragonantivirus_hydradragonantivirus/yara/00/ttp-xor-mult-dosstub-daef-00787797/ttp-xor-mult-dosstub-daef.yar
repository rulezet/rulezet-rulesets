rule TTP_XOR_MULT_DOSStub_daef {
  strings:
    $key_daef = { 8e 87 [2] fa 9f [2] bd 9d [2] fa 8c [2] b4 80 [2] b8 8a [2] af 81 [2] b4 cf [2] 89 }

  condition:
    any of them
}