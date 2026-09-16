rule TTP_XOR_MULT_DOSStub_d76c {
  strings:
    $key_d76c = { 83 04 [2] f7 1c [2] b0 1e [2] f7 0f [2] b9 03 [2] b5 09 [2] a2 02 [2] b9 4c [2] 84 }

  condition:
    any of them
}