rule TTP_XOR_WriteProcessMemory_bacb {
  strings:
    $key_bacb = { ed b9 [2] df 9b [2] d9 ae [2] f7 ae [2] c8 b2 }

  condition:
    any of them
}