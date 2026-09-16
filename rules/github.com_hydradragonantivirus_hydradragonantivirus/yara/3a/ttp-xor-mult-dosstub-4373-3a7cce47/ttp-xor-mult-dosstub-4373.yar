rule TTP_XOR_MULT_DOSStub_4373 {
  strings:
    $key_4373 = { 17 1b [2] 63 03 [2] 24 01 [2] 63 10 [2] 2d 1c [2] 21 16 [2] 36 1d [2] 2d 53 [2] 10 }

  condition:
    any of them
}