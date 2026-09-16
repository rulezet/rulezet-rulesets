rule TTP_XOR_MULT_DOSStub_c9ed {
  strings:
    $key_c9ed = { 9d 85 [2] e9 9d [2] ae 9f [2] e9 8e [2] a7 82 [2] ab 88 [2] bc 83 [2] a7 cd [2] 9a }

  condition:
    any of them
}