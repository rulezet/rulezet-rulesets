rule TTP_XOR_MULT_DOSStub_c5ea {
  strings:
    $key_c5ea = { 91 82 [2] e5 9a [2] a2 98 [2] e5 89 [2] ab 85 [2] a7 8f [2] b0 84 [2] ab ca [2] 96 }

  condition:
    any of them
}