rule TTP_XOR_MULT_DOSStub_dacd {
  strings:
    $key_dacd = { 8e a5 [2] fa bd [2] bd bf [2] fa ae [2] b4 a2 [2] b8 a8 [2] af a3 [2] b4 ed [2] 89 }

  condition:
    any of them
}