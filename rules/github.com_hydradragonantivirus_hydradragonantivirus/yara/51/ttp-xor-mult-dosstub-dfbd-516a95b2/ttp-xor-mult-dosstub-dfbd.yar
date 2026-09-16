rule TTP_XOR_MULT_DOSStub_dfbd {
  strings:
    $key_dfbd = { 8b d5 [2] ff cd [2] b8 cf [2] ff de [2] b1 d2 [2] bd d8 [2] aa d3 [2] b1 9d [2] 8c }

  condition:
    any of them
}