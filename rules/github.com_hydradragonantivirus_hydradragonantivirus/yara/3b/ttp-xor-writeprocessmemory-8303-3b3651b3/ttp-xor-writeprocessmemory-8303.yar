rule TTP_XOR_WriteProcessMemory_8303 {
  strings:
    $key_8303 = { d4 71 [2] e6 53 [2] e0 66 [2] ce 66 [2] f1 7a }

  condition:
    any of them
}