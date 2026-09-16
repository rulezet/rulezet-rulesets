rule TTP_XOR_MULT_DOSStub_bfbf {
  strings:
    $key_bfbf = { eb d7 [2] 9f cf [2] d8 cd [2] 9f dc [2] d1 d0 [2] dd da [2] ca d1 [2] d1 9f [2] ec }

  condition:
    any of them
}