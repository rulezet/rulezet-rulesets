rule TTP_XOR_MULT_DOSStub_e943 {
  strings:
    $key_e943 = { bd 2b [2] c9 33 [2] 8e 31 [2] c9 20 [2] 87 2c [2] 8b 26 [2] 9c 2d [2] 87 63 [2] ba }

  condition:
    any of them
}