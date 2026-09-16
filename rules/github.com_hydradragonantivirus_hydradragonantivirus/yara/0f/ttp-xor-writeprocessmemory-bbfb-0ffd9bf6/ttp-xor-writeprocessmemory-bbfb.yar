rule TTP_XOR_WriteProcessMemory_bbfb {
  strings:
    $key_bbfb = { ec 89 [2] de ab [2] d8 9e [2] f6 9e [2] c9 82 }

  condition:
    any of them
}