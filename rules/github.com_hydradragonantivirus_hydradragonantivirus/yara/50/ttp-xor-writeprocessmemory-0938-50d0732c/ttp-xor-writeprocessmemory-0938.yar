rule TTP_XOR_WriteProcessMemory_0938 {
  strings:
    $key_0938 = { 5e 4a [2] 6c 68 [2] 6a 5d [2] 44 5d [2] 7b 41 }

  condition:
    any of them
}