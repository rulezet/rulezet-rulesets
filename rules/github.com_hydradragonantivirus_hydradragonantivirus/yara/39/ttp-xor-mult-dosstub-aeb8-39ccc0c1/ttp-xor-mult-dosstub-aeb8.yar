rule TTP_XOR_MULT_DOSStub_aeb8 {
  strings:
    $key_aeb8 = { fa d0 [2] 8e c8 [2] c9 ca [2] 8e db [2] c0 d7 [2] cc dd [2] db d6 [2] c0 98 [2] fd }

  condition:
    any of them
}