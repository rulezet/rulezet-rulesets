rule TTP_XOR_MULT_DOSStub_e91d {
  strings:
    $key_e91d = { bd 75 [2] c9 6d [2] 8e 6f [2] c9 7e [2] 87 72 [2] 8b 78 [2] 9c 73 [2] 87 3d [2] ba }

  condition:
    any of them
}