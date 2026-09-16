rule TTP_XOR_MULT_DOSStub_0baf {
  strings:
    $key_0baf = { 5f c7 [2] 2b df [2] 6c dd [2] 2b cc [2] 65 c0 [2] 69 ca [2] 7e c1 [2] 65 8f [2] 58 }

  condition:
    any of them
}