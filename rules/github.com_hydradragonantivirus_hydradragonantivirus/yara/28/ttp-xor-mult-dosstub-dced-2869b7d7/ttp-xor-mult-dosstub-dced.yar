rule TTP_XOR_MULT_DOSStub_dced {
  strings:
    $key_dced = { 88 85 [2] fc 9d [2] bb 9f [2] fc 8e [2] b2 82 [2] be 88 [2] a9 83 [2] b2 cd [2] 8f }

  condition:
    any of them
}