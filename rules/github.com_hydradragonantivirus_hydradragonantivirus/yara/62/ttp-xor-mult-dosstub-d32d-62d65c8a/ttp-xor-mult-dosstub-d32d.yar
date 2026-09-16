rule TTP_XOR_MULT_DOSStub_d32d {
  strings:
    $key_d32d = { 87 45 [2] f3 5d [2] b4 5f [2] f3 4e [2] bd 42 [2] b1 48 [2] a6 43 [2] bd 0d [2] 80 }

  condition:
    any of them
}