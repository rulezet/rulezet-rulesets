rule TTP_XOR_WriteProcessMemory_3138 {
  strings:
    $key_3138 = { 66 4a [2] 54 68 [2] 52 5d [2] 7c 5d [2] 43 41 }

  condition:
    any of them
}