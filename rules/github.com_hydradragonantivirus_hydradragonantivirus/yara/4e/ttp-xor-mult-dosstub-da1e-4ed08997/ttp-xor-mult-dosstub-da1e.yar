rule TTP_XOR_MULT_DOSStub_da1e {
  strings:
    $key_da1e = { 8e 76 [2] fa 6e [2] bd 6c [2] fa 7d [2] b4 71 [2] b8 7b [2] af 70 [2] b4 3e [2] 89 }

  condition:
    any of them
}