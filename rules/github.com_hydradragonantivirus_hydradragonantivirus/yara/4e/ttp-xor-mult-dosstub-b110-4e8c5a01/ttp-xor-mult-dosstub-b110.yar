rule TTP_XOR_MULT_DOSStub_b110 {
  strings:
    $key_b110 = { e5 78 [2] 91 60 [2] d6 62 [2] 91 73 [2] df 7f [2] d3 75 [2] c4 7e [2] df 30 [2] e2 }

  condition:
    any of them
}