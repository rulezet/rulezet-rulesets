rule TTP_XOR_MULT_DOSStub_da2e {
  strings:
    $key_da2e = { 8e 46 [2] fa 5e [2] bd 5c [2] fa 4d [2] b4 41 [2] b8 4b [2] af 40 [2] b4 0e [2] 89 }

  condition:
    any of them
}