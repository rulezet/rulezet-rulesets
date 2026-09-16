rule TTP_XOR_MULT_DOSStub_2faf {
  strings:
    $key_2faf = { 7b c7 [2] 0f df [2] 48 dd [2] 0f cc [2] 41 c0 [2] 4d ca [2] 5a c1 [2] 41 8f [2] 7c }

  condition:
    any of them
}