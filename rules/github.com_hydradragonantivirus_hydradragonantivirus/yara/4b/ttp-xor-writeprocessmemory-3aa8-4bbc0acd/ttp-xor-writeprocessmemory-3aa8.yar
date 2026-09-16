rule TTP_XOR_WriteProcessMemory_3aa8 {
  strings:
    $key_3aa8 = { 6d da [2] 5f f8 [2] 59 cd [2] 77 cd [2] 48 d1 }

  condition:
    any of them
}