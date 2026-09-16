rule TTP_XOR_WriteProcessMemory_0469 {
  strings:
    $key_0469 = { 53 1b [2] 61 39 [2] 67 0c [2] 49 0c [2] 76 10 }

  condition:
    any of them
}