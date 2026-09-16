rule TTP_XOR_MULT_DOSStub_c229 {
  strings:
    $key_c229 = { 96 41 [2] e2 59 [2] a5 5b [2] e2 4a [2] ac 46 [2] a0 4c [2] b7 47 [2] ac 09 [2] 91 }

  condition:
    any of them
}