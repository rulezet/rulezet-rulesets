rule TTP_XOR_MULT_DOSStub_ddba {
  strings:
    $key_ddba = { 89 d2 [2] fd ca [2] ba c8 [2] fd d9 [2] b3 d5 [2] bf df [2] a8 d4 [2] b3 9a [2] 8e }

  condition:
    any of them
}