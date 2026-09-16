rule TTP_XOR_WriteProcessMemory_7fe8 {
  strings:
    $key_7fe8 = { 28 9a [2] 1a b8 [2] 1c 8d [2] 32 8d [2] 0d 91 }

  condition:
    any of them
}