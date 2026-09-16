rule TTP_XOR_WriteProcessMemory_70fe {
  strings:
    $key_70fe = { 27 8c [2] 15 ae [2] 13 9b [2] 3d 9b [2] 02 87 }

  condition:
    any of them
}