rule TTP_XOR_MULT_DOSStub_dfce {
  strings:
    $key_dfce = { 8b a6 [2] ff be [2] b8 bc [2] ff ad [2] b1 a1 [2] bd ab [2] aa a0 [2] b1 ee [2] 8c }

  condition:
    any of them
}