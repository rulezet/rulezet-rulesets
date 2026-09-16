rule TTP_XOR_WriteProcessMemory_bb89 {
  strings:
    $key_bb89 = { ec fb [2] de d9 [2] d8 ec [2] f6 ec [2] c9 f0 }

  condition:
    any of them
}