rule TTP_XOR_MULT_DOSStub_d46c {
  strings:
    $key_d46c = { 80 04 [2] f4 1c [2] b3 1e [2] f4 0f [2] ba 03 [2] b6 09 [2] a1 02 [2] ba 4c [2] 87 }

  condition:
    any of them
}