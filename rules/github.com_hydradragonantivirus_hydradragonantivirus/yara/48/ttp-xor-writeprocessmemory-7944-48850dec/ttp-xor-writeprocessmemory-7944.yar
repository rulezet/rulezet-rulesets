rule TTP_XOR_WriteProcessMemory_7944 {
  strings:
    $key_7944 = { 2e 36 [2] 1c 14 [2] 1a 21 [2] 34 21 [2] 0b 3d }

  condition:
    any of them
}