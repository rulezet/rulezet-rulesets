rule TTP_XOR_MULT_DOSStub_ccaf {
  strings:
    $key_ccaf = { 98 c7 [2] ec df [2] ab dd [2] ec cc [2] a2 c0 [2] ae ca [2] b9 c1 [2] a2 8f [2] 9f }

  condition:
    any of them
}