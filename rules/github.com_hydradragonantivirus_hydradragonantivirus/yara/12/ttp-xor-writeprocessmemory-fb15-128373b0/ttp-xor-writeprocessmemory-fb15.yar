rule TTP_XOR_WriteProcessMemory_fb15 {
  strings:
    $key_fb15 = { ac 67 [2] 9e 45 [2] 98 70 [2] b6 70 [2] 89 6c }

  condition:
    any of them
}