rule TTP_XOR_MULT_DOSStub_ea9c {
  strings:
    $key_ea9c = { be f4 [2] ca ec [2] 8d ee [2] ca ff [2] 84 f3 [2] 88 f9 [2] 9f f2 [2] 84 bc [2] b9 }

  condition:
    any of them
}