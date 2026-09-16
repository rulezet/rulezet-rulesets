rule TTP_XOR_MULT_DOSStub_c9bf {
  strings:
    $key_c9bf = { 9d d7 [2] e9 cf [2] ae cd [2] e9 dc [2] a7 d0 [2] ab da [2] bc d1 [2] a7 9f [2] 9a }

  condition:
    any of them
}