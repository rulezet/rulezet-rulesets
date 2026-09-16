rule TTP_XOR_WriteProcessMemory_1aa8 {
  strings:
    $key_1aa8 = { 4d da [2] 7f f8 [2] 79 cd [2] 57 cd [2] 68 d1 }

  condition:
    any of them
}