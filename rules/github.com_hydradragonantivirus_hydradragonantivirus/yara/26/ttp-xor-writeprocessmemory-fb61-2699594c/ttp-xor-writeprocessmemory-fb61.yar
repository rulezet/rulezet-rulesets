rule TTP_XOR_WriteProcessMemory_fb61 {
  strings:
    $key_fb61 = { ac 13 [2] 9e 31 [2] 98 04 [2] b6 04 [2] 89 18 }

  condition:
    any of them
}