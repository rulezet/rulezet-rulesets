rule TTP_XOR_MULT_DOSStub_ffce {
  strings:
    $key_ffce = { ab a6 [2] df be [2] 98 bc [2] df ad [2] 91 a1 [2] 9d ab [2] 8a a0 [2] 91 ee [2] ac }

  condition:
    any of them
}