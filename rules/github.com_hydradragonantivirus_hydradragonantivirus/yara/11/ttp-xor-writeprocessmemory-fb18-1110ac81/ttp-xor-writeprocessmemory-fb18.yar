rule TTP_XOR_WriteProcessMemory_fb18 {
  strings:
    $key_fb18 = { ac 6a [2] 9e 48 [2] 98 7d [2] b6 7d [2] 89 61 }

  condition:
    any of them
}