rule TTP_XOR_MULT_DOSStub_eabd {
  strings:
    $key_eabd = { be d5 [2] ca cd [2] 8d cf [2] ca de [2] 84 d2 [2] 88 d8 [2] 9f d3 [2] 84 9d [2] b9 }

  condition:
    any of them
}