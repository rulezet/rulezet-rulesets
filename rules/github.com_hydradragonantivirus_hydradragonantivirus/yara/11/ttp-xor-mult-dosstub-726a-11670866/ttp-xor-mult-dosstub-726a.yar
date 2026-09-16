rule TTP_XOR_MULT_DOSStub_726a {
  strings:
    $key_726a = { 26 02 [2] 52 1a [2] 15 18 [2] 52 09 [2] 1c 05 [2] 10 0f [2] 07 04 [2] 1c 4a [2] 21 }

  condition:
    any of them
}