rule TTP_XOR_MULT_DOSStub_d0ea {
  strings:
    $key_d0ea = { 84 82 [2] f0 9a [2] b7 98 [2] f0 89 [2] be 85 [2] b2 8f [2] a5 84 [2] be ca [2] 83 }

  condition:
    any of them
}