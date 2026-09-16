rule TTP_XOR_MULT_DOSStub_51ef {
  strings:
    $key_51ef = { 05 87 [2] 71 9f [2] 36 9d [2] 71 8c [2] 3f 80 [2] 33 8a [2] 24 81 [2] 3f cf [2] 02 }

  condition:
    any of them
}