rule TTP_XOR_MULT_DOSStub_4834 {
  strings:
    $key_4834 = { 1c 5c [2] 68 44 [2] 2f 46 [2] 68 57 [2] 26 5b [2] 2a 51 [2] 3d 5a [2] 26 14 [2] 1b }

  condition:
    any of them
}