rule TTP_XOR_WriteProcessMemory_0418 {
  strings:
    $key_0418 = { 53 6a [2] 61 48 [2] 67 7d [2] 49 7d [2] 76 61 }

  condition:
    any of them
}