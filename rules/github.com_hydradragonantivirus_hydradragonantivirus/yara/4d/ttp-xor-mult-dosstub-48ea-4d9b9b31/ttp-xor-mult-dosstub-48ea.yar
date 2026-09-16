rule TTP_XOR_MULT_DOSStub_48ea {
  strings:
    $key_48ea = { 1c 82 [2] 68 9a [2] 2f 98 [2] 68 89 [2] 26 85 [2] 2a 8f [2] 3d 84 [2] 26 ca [2] 1b }

  condition:
    any of them
}