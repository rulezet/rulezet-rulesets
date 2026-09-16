rule TTP_XOR_WriteProcessMemory_2aa8 {
  strings:
    $key_2aa8 = { 7d da [2] 4f f8 [2] 49 cd [2] 67 cd [2] 58 d1 }

  condition:
    any of them
}