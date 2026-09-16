rule TTP_XOR_MULT_DOSStub_c46c {
  strings:
    $key_c46c = { 90 04 [2] e4 1c [2] a3 1e [2] e4 0f [2] aa 03 [2] a6 09 [2] b1 02 [2] aa 4c [2] 97 }

  condition:
    any of them
}