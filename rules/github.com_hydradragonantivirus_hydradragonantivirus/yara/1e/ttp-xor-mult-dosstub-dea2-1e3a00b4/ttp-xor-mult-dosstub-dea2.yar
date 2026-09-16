rule TTP_XOR_MULT_DOSStub_dea2 {
  strings:
    $key_dea2 = { 8a ca [2] fe d2 [2] b9 d0 [2] fe c1 [2] b0 cd [2] bc c7 [2] ab cc [2] b0 82 [2] 8d }

  condition:
    any of them
}