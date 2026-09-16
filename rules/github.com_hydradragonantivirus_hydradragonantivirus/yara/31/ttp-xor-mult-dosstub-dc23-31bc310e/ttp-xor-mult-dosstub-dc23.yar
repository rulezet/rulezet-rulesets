rule TTP_XOR_MULT_DOSStub_dc23 {
  strings:
    $key_dc23 = { 88 4b [2] fc 53 [2] bb 51 [2] fc 40 [2] b2 4c [2] be 46 [2] a9 4d [2] b2 03 [2] 8f }

  condition:
    any of them
}