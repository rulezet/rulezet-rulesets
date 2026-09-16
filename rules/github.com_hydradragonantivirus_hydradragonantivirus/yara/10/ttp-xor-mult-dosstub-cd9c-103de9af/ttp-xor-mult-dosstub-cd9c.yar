rule TTP_XOR_MULT_DOSStub_cd9c {
  strings:
    $key_cd9c = { 99 f4 [2] ed ec [2] aa ee [2] ed ff [2] a3 f3 [2] af f9 [2] b8 f2 [2] a3 bc [2] 9e }

  condition:
    any of them
}