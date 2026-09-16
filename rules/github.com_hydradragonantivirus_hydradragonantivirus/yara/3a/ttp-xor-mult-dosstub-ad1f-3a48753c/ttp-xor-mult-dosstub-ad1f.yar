rule TTP_XOR_MULT_DOSStub_ad1f {
  strings:
    $key_ad1f = { f9 77 [2] 8d 6f [2] ca 6d [2] 8d 7c [2] c3 70 [2] cf 7a [2] d8 71 [2] c3 3f [2] fe }

  condition:
    any of them
}