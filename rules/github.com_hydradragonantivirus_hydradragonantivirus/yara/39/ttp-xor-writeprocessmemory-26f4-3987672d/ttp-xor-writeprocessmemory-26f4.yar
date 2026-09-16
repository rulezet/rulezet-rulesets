rule TTP_XOR_WriteProcessMemory_26f4 {
  strings:
    $key_26f4 = { 71 86 [2] 43 a4 [2] 45 91 [2] 6b 91 [2] 54 8d }

  condition:
    any of them
}