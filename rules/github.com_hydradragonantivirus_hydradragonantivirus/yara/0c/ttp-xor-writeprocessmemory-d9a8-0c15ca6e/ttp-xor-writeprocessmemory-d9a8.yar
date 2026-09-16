rule TTP_XOR_WriteProcessMemory_d9a8 {
  strings:
    $key_d9a8 = { 8e da [2] bc f8 [2] ba cd [2] 94 cd [2] ab d1 }

  condition:
    any of them
}