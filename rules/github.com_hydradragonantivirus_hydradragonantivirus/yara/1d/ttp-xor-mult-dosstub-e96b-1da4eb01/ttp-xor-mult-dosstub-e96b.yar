rule TTP_XOR_MULT_DOSStub_e96b {
  strings:
    $key_e96b = { bd 03 [2] c9 1b [2] 8e 19 [2] c9 08 [2] 87 04 [2] 8b 0e [2] 9c 05 [2] 87 4b [2] ba }

  condition:
    any of them
}