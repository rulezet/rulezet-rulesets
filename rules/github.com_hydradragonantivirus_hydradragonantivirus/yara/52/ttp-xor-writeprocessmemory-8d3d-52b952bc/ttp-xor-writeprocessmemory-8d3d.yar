rule TTP_XOR_WriteProcessMemory_8d3d {
  strings:
    $key_8d3d = { da 4f [2] e8 6d [2] ee 58 [2] c0 58 [2] ff 44 }

  condition:
    any of them
}