rule TTP_XOR_MULT_DOSStub_a2ed {
  strings:
    $key_a2ed = { f6 85 [2] 82 9d [2] c5 9f [2] 82 8e [2] cc 82 [2] c0 88 [2] d7 83 [2] cc cd [2] f1 }

  condition:
    any of them
}