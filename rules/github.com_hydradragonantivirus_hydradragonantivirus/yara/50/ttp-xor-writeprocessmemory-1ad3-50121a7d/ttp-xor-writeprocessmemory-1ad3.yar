rule TTP_XOR_WriteProcessMemory_1ad3 {
  strings:
    $key_1ad3 = { 4d a1 [2] 7f 83 [2] 79 b6 [2] 57 b6 [2] 68 aa }

  condition:
    any of them
}