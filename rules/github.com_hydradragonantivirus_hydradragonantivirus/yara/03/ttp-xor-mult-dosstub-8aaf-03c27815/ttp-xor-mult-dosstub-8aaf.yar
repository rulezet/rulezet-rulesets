rule TTP_XOR_MULT_DOSStub_8aaf {
  strings:
    $key_8aaf = { de c7 [2] aa df [2] ed dd [2] aa cc [2] e4 c0 [2] e8 ca [2] ff c1 [2] e4 8f [2] d9 }

  condition:
    any of them
}