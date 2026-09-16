rule TTP_XOR_WriteProcessMemory_0644 {
  strings:
    $key_0644 = { 51 36 [2] 63 14 [2] 65 21 [2] 4b 21 [2] 74 3d }

  condition:
    any of them
}