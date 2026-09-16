rule TTP_XOR_MULT_DOSStub_a866 {
  strings:
    $key_a866 = { fc 0e [2] 88 16 [2] cf 14 [2] 88 05 [2] c6 09 [2] ca 03 [2] dd 08 [2] c6 46 [2] fb }

  condition:
    any of them
}