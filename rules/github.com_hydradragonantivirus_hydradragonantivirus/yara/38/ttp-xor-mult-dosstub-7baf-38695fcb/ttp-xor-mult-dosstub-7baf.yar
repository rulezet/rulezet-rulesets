rule TTP_XOR_MULT_DOSStub_7baf {
  strings:
    $key_7baf = { 2f c7 [2] 5b df [2] 1c dd [2] 5b cc [2] 15 c0 [2] 19 ca [2] 0e c1 [2] 15 8f [2] 28 }

  condition:
    any of them
}