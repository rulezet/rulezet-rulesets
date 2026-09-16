rule TTP_XOR_MULT_DOSStub_3cea {
  strings:
    $key_3cea = { 68 82 [2] 1c 9a [2] 5b 98 [2] 1c 89 [2] 52 85 [2] 5e 8f [2] 49 84 [2] 52 ca [2] 6f }

  condition:
    any of them
}