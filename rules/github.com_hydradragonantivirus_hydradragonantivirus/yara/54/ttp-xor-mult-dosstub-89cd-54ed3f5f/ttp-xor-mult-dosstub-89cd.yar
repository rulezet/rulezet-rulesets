rule TTP_XOR_MULT_DOSStub_89cd {
  strings:
    $key_89cd = { dd a5 [2] a9 bd [2] ee bf [2] a9 ae [2] e7 a2 [2] eb a8 [2] fc a3 [2] e7 ed [2] da }

  condition:
    any of them
}