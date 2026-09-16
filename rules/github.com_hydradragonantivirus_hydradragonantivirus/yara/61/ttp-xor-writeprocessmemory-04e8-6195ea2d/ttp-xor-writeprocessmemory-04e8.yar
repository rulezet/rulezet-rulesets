rule TTP_XOR_WriteProcessMemory_04e8 {
  strings:
    $key_04e8 = { 53 9a [2] 61 b8 [2] 67 8d [2] 49 8d [2] 76 91 }

  condition:
    any of them
}