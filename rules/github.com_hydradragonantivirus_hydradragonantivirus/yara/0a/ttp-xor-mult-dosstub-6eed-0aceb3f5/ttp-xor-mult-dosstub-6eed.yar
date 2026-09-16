rule TTP_XOR_MULT_DOSStub_6eed {
  strings:
    $key_6eed = { 3a 85 [2] 4e 9d [2] 09 9f [2] 4e 8e [2] 00 82 [2] 0c 88 [2] 1b 83 [2] 00 cd [2] 3d }

  condition:
    any of them
}