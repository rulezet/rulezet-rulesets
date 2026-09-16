rule TTP_XOR_MULT_DOSStub_dafe {
  strings:
    $key_dafe = { 8e 96 [2] fa 8e [2] bd 8c [2] fa 9d [2] b4 91 [2] b8 9b [2] af 90 [2] b4 de [2] 89 }

  condition:
    any of them
}