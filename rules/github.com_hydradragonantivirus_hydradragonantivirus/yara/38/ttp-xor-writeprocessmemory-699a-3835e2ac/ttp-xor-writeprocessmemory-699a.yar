rule TTP_XOR_WriteProcessMemory_699a {
  strings:
    $key_699a = { 3e e8 [2] 0c ca [2] 0a ff [2] 24 ff [2] 1b e3 }

  condition:
    any of them
}