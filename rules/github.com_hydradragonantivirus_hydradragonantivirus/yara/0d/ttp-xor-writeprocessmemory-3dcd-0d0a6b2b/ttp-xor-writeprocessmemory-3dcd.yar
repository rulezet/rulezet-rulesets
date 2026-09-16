rule TTP_XOR_WriteProcessMemory_3dcd {
  strings:
    $key_3dcd = { 6a bf [2] 58 9d [2] 5e a8 [2] 70 a8 [2] 4f b4 }

  condition:
    any of them
}