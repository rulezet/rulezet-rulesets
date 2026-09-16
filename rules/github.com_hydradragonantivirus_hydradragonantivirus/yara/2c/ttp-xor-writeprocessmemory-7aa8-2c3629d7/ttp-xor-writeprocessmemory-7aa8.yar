rule TTP_XOR_WriteProcessMemory_7aa8 {
  strings:
    $key_7aa8 = { 2d da [2] 1f f8 [2] 19 cd [2] 37 cd [2] 08 d1 }

  condition:
    any of them
}