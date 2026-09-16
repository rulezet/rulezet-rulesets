rule TTP_XOR_WriteProcessMemory_0628 {
  strings:
    $key_0628 = { 51 5a [2] 63 78 [2] 65 4d [2] 4b 4d [2] 74 51 }

  condition:
    any of them
}