rule TTP_XOR_WriteProcessMemory_0317 {
  strings:
    $key_0317 = { 54 65 [2] 66 47 [2] 60 72 [2] 4e 72 [2] 71 6e }

  condition:
    any of them
}