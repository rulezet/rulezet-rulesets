rule TTP_XOR_MULT_DOSStub_c8bd {
  strings:
    $key_c8bd = { 9c d5 [2] e8 cd [2] af cf [2] e8 de [2] a6 d2 [2] aa d8 [2] bd d3 [2] a6 9d [2] 9b }

  condition:
    any of them
}