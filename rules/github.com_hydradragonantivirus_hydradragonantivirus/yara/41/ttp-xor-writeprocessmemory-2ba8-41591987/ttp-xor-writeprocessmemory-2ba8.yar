rule TTP_XOR_WriteProcessMemory_2ba8 {
  strings:
    $key_2ba8 = { 7c da [2] 4e f8 [2] 48 cd [2] 66 cd [2] 59 d1 }

  condition:
    any of them
}