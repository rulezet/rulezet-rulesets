rule TTP_XOR_MULT_DOSStub_a8ba {
  strings:
    $key_a8ba = { fc d2 [2] 88 ca [2] cf c8 [2] 88 d9 [2] c6 d5 [2] ca df [2] dd d4 [2] c6 9a [2] fb }

  condition:
    any of them
}