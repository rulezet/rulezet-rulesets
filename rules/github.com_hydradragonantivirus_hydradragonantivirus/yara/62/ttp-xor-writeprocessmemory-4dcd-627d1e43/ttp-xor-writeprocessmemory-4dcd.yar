rule TTP_XOR_WriteProcessMemory_4dcd {
  strings:
    $key_4dcd = { 1a bf [2] 28 9d [2] 2e a8 [2] 00 a8 [2] 3f b4 }

  condition:
    any of them
}