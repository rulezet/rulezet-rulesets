rule TTP_XOR_MULT_DOSStub_dda5 {
  strings:
    $key_dda5 = { 89 cd [2] fd d5 [2] ba d7 [2] fd c6 [2] b3 ca [2] bf c0 [2] a8 cb [2] b3 85 [2] 8e }

  condition:
    any of them
}