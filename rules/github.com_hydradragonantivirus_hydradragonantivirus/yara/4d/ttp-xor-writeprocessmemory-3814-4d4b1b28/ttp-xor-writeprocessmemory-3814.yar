rule TTP_XOR_WriteProcessMemory_3814 {
  strings:
    $key_3814 = { 6f 66 [2] 5d 44 [2] 5b 71 [2] 75 71 [2] 4a 6d }

  condition:
    any of them
}