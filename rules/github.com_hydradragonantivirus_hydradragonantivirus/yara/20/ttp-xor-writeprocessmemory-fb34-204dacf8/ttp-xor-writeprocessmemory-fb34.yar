rule TTP_XOR_WriteProcessMemory_fb34 {
  strings:
    $key_fb34 = { ac 46 [2] 9e 64 [2] 98 51 [2] b6 51 [2] 89 4d }

  condition:
    any of them
}