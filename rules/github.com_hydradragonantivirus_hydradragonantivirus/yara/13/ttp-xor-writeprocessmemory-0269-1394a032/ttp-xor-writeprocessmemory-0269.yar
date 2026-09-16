rule TTP_XOR_WriteProcessMemory_0269 {
  strings:
    $key_0269 = { 55 1b [2] 67 39 [2] 61 0c [2] 4f 0c [2] 70 10 }

  condition:
    any of them
}