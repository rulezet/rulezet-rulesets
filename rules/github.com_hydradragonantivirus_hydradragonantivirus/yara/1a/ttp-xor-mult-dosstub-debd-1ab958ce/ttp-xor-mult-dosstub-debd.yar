rule TTP_XOR_MULT_DOSStub_debd {
  strings:
    $key_debd = { 8a d5 [2] fe cd [2] b9 cf [2] fe de [2] b0 d2 [2] bc d8 [2] ab d3 [2] b0 9d [2] 8d }

  condition:
    any of them
}