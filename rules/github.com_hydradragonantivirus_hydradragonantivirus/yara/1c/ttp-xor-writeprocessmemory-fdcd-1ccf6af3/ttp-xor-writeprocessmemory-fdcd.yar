rule TTP_XOR_WriteProcessMemory_fdcd {
  strings:
    $key_fdcd = { aa bf [2] 98 9d [2] 9e a8 [2] b0 a8 [2] 8f b4 }

  condition:
    any of them
}