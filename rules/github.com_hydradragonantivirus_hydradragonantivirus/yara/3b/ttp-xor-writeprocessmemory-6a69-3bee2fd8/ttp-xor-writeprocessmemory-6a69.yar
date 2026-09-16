rule TTP_XOR_WriteProcessMemory_6a69 {
  strings:
    $key_6a69 = { 3d 1b [2] 0f 39 [2] 09 0c [2] 27 0c [2] 18 10 }

  condition:
    any of them
}