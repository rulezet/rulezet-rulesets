rule TTP_XOR_MULT_DOSStub_daaf {
  strings:
    $key_daaf = { 8e c7 [2] fa df [2] bd dd [2] fa cc [2] b4 c0 [2] b8 ca [2] af c1 [2] b4 8f [2] 89 }

  condition:
    any of them
}