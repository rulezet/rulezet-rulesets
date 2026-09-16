rule TTP_XOR_WriteProcessMemory_6a8e {
  strings:
    $key_6a8e = { 3d fc [2] 0f de [2] 09 eb [2] 27 eb [2] 18 f7 }

  condition:
    any of them
}