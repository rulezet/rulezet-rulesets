rule TTP_XOR_WriteProcessMemory_3018 {
  strings:
    $key_3018 = { 67 6a [2] 55 48 [2] 53 7d [2] 7d 7d [2] 42 61 }

  condition:
    any of them
}