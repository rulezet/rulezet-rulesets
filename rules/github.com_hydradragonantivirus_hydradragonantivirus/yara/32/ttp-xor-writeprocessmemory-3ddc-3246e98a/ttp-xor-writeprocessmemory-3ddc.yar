rule TTP_XOR_WriteProcessMemory_3ddc {
  strings:
    $key_3ddc = { 6a ae [2] 58 8c [2] 5e b9 [2] 70 b9 [2] 4f a5 }

  condition:
    any of them
}