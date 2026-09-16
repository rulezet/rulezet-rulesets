rule TTP_XOR_WriteProcessMemory_0438 {
  strings:
    $key_0438 = { 53 4a [2] 61 68 [2] 67 5d [2] 49 5d [2] 76 41 }

  condition:
    any of them
}