rule TTP_XOR_WriteProcessMemory_0f28 {
  strings:
    $key_0f28 = { 58 5a [2] 6a 78 [2] 6c 4d [2] 42 4d [2] 7d 51 }

  condition:
    any of them
}