rule TTP_XOR_WriteProcessMemory_299a {
  strings:
    $key_299a = { 7e e8 [2] 4c ca [2] 4a ff [2] 64 ff [2] 5b e3 }

  condition:
    any of them
}