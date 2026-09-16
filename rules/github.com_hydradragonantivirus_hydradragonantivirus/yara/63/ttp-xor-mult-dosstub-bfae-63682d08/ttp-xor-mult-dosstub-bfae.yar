rule TTP_XOR_MULT_DOSStub_bfae {
  strings:
    $key_bfae = { eb c6 [2] 9f de [2] d8 dc [2] 9f cd [2] d1 c1 [2] dd cb [2] ca c0 [2] d1 8e [2] ec }

  condition:
    any of them
}