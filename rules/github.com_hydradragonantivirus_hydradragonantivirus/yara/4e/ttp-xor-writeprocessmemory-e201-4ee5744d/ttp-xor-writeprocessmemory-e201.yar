rule TTP_XOR_WriteProcessMemory_e201 {
  strings:
    $key_e201 = { b5 73 [2] 87 51 [2] 81 64 [2] af 64 [2] 90 78 }

  condition:
    any of them
}