rule TTP_XOR_MULT_DOSStub_932d {
  strings:
    $key_932d = { c7 45 [2] b3 5d [2] f4 5f [2] b3 4e [2] fd 42 [2] f1 48 [2] e6 43 [2] fd 0d [2] c0 }

  condition:
    any of them
}