rule TTP_XOR_WriteProcessMemory_fb23 {
  strings:
    $key_fb23 = { ac 51 [2] 9e 73 [2] 98 46 [2] b6 46 [2] 89 5a }

  condition:
    any of them
}