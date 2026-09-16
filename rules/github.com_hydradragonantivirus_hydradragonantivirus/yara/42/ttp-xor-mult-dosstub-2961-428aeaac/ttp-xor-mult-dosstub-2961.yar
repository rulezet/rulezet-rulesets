rule TTP_XOR_MULT_DOSStub_2961 {
  strings:
    $key_2961 = { 7d 09 [2] 09 11 [2] 4e 13 [2] 09 02 [2] 47 0e [2] 4b 04 [2] 5c 0f [2] 47 41 [2] 7a }

  condition:
    any of them
}