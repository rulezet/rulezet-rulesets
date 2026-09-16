rule TTP_XOR_MULT_DOSStub_eafe {
  strings:
    $key_eafe = { be 96 [2] ca 8e [2] 8d 8c [2] ca 9d [2] 84 91 [2] 88 9b [2] 9f 90 [2] 84 de [2] b9 }

  condition:
    any of them
}