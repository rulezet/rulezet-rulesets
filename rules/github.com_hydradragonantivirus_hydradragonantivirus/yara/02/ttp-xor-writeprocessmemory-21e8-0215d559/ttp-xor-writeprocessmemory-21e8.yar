rule TTP_XOR_WriteProcessMemory_21e8 {
  strings:
    $key_21e8 = { 76 9a [2] 44 b8 [2] 42 8d [2] 6c 8d [2] 53 91 }

  condition:
    any of them
}