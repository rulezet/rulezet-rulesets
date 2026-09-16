rule TTP_XOR_MULT_DOSStub_dda3 {
  strings:
    $key_dda3 = { 89 cb [2] fd d3 [2] ba d1 [2] fd c0 [2] b3 cc [2] bf c6 [2] a8 cd [2] b3 83 [2] 8e }

  condition:
    any of them
}