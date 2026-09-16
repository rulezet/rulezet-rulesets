rule TTP_XOR_MULT_DOSStub_48ed {
  strings:
    $key_48ed = { 1c 85 [2] 68 9d [2] 2f 9f [2] 68 8e [2] 26 82 [2] 2a 88 [2] 3d 83 [2] 26 cd [2] 1b }

  condition:
    any of them
}