rule TTP_XOR_WriteProcessMemory_6903 {
  strings:
    $key_6903 = { 3e 71 [2] 0c 53 [2] 0a 66 [2] 24 66 [2] 1b 7a }

  condition:
    any of them
}